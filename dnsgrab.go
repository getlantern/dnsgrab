package dnsgrab

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/dns"
	"github.com/getlantern/dnsgrab/common"
	"github.com/getlantern/golog"
	"github.com/getlantern/netx"
)

const (
	maxUDPPacketSize = 512
)

var (
	log = golog.LoggerFor("dnsgrab")
)

// Server is a dns server that resolves queries for A records into fake IP
// addresses within the Class-E address space and allows reverse resolution of
// those back into the originally queried hostname.
type Server interface {
	// LocalAddr() returns the address at which this server is listening
	LocalAddr() net.Addr

	// Serve() runs the server (blocks until server ends)
	Serve() error

	// Close closes the server's network listener.
	Close() error

	// ProcessQuery processes a DNS query and returns the response bytes.
	ProcessQuery(b []byte) ([]byte, error)

	// ReverseLookup resolves the given fake IP address into the original hostname. If the given IP is not a fake IP,
	// this simply returns the provided IP in string form. If the IP is not found, this returns false.
	ReverseLookup(ip net.IP) (string, bool)
}

// Cache defines the API for a cache of names to IPs and vice versa
type Cache interface {
	NameByIP(ip []byte) (name string, found bool)

	IPByName(name string) (ip []byte, found bool)

	Add(name string, ip []byte)

	MarkFresh(name string, ip []byte)

	NextSequence() uint32
}

type server struct {
	cache            Cache
	defaultDNSServer string
	conn             *net.UDPConn
	client           *dns.Client
	mx               sync.RWMutex
}

// Listen creates a new server listening at the given listenAddr and that
// forwards queries it can't handle to the given defaultDNSServer. It uses an
// in-memory cache constrained by cacheSize.
func Listen(cacheSize int, listenAddr string, defaultDNSServer string) (Server, error) {
	return ListenWithCache(listenAddr, defaultDNSServer, NewInMemoryCache(cacheSize))
}

// ListenWithCache is like Listen but taking any Cache implementation.
func ListenWithCache(listenAddr string, defaultDNSServer string, cache Cache) (Server, error) {
	_, _, err := net.SplitHostPort(defaultDNSServer)
	if err != nil {
		defaultDNSServer = defaultDNSServer + ":53"
		log.Debugf("Defaulted port for defaultDNSServer to 53: %v", defaultDNSServer)
	}

	s := &server{
		cache:            cache,
		defaultDNSServer: defaultDNSServer,
		client: &dns.Client{
			ReadTimeout: 2 * time.Second,
			Dial:        netx.DialTimeout,
		},
	}

	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	s.conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}

	log.Debugf("Listening at: %v", s.conn.LocalAddr())
	return s, nil
}

func (s *server) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *server) Serve() error {
	b := make([]byte, maxUDPPacketSize)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(b)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed") {
				log.Error(err)
			}
			continue
		}
		go s.handle(b[:n], remoteAddr)
	}
}

func (s *server) Close() error {
	return s.conn.Close()
}

func (s *server) ReverseLookup(ip net.IP) (string, bool) {
	ipInt := common.IPToInt(ip)
	if ipInt < common.MinIP || ipInt > common.MaxIP {
		return ip.String(), true
	}
	s.mx.RLock()
	result, found := s.cache.NameByIP(ip.To4())
	s.mx.RUnlock()
	if !found {
		return "", false
	}
	return result, true
}

func (s *server) ProcessQuery(b []byte) ([]byte, error) {
	msgIn := &dns.Msg{}
	msgIn.Unpack(b)

	if len(msgIn.Question) == 0 {
		// TODO: forward the message upstream
	}

	msgOut := &dns.Msg{}
	msgOut.Response = true
	msgOut.Id = msgIn.Id
	msgOut.Question = msgIn.Question
	var unansweredQuestions []dns.Question

	for _, question := range msgIn.Question {
		answer := s.processQuestion(question)
		if answer != nil {
			msgOut.Answer = append(msgOut.Answer, answer)
		} else {
			unansweredQuestions = append(unansweredQuestions, question)
		}
	}

	if len(unansweredQuestions) > 0 {
		log.Debugf("Passing unanswered questions along: %v", unansweredQuestions)
		msgIn.Question = unansweredQuestions
		resp, _, err := s.client.Exchange(msgIn, s.defaultDNSServer)
		if err != nil {
			return nil, err
		}
		msgOut.Answer = append(msgOut.Answer, resp.Answer...)
	}

	return msgOut.Pack()
}

func (s *server) handle(b []byte, remoteAddr *net.UDPAddr) {
	bo, err := s.ProcessQuery(b)
	if err != nil {
		log.Error(err)
		return
	}

	_, writeErr := s.conn.WriteToUDP(bo, remoteAddr)
	if writeErr != nil {
		log.Errorf("Error responding to DNS query: %v", writeErr)
	}
}

func (s *server) processAQuestion(question dns.Question) dns.RR {
	answer := &dns.A{}
	// Short TTL should be fine since these DNS lookups are local and should be quite cheap
	answer.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}
	name := stripTrailingDot(question.Name)
	s.mx.Lock()
	ip, found := s.cache.IPByName(name)
	if found {
		s.cache.MarkFresh(name, ip)
	} else {
		// get next fake IP from sequence
		ip = common.IntToIP(s.cache.NextSequence())
		s.cache.Add(name, ip)
	}
	fakeIP := net.IP(ip)
	s.mx.Unlock()
	log.Debugf("resolved %v -> %v", name, fakeIP.String())
	answer.A = fakeIP
	return answer
}

func (s *server) processQuestion(question dns.Question) dns.RR {
	if question.Qclass != dns.ClassINET {
		return nil
	}
	if question.Qtype == dns.TypeA {
		return s.processAQuestion(question)
	}
	if question.Qtype == dns.TypePTR {
		return s.processPTRQuestion(question)
	}
	return nil
}

func (s *server) processPTRQuestion(question dns.Question) dns.RR {
	answer := &dns.PTR{}
	// Short TTL should be fine since these DNS lookups are local and should be quite cheap
	answer.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 1}
	parts := strings.Split(question.Name, ".")
	if len(parts) < 4 {
		return nil
	}
	parts = parts[:4]
	parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
	ipString := strings.Join(parts, ".")
	ip := net.ParseIP(ipString).To4()
	if len(ip) != 4 {
		return nil
	}
	s.mx.Lock()
	name, found := s.cache.NameByIP(ip.To4())
	s.mx.Unlock()
	if !found {
		return nil
	}
	log.Debugf("reversed %v -> %v", question.Name, name)
	answer.Ptr = name + "."
	return answer
}

func stripTrailingDot(name string) string {
	// strip trailing dot
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
