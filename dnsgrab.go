package dnsgrab

import (
	"container/list"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/getlantern/dns"
	"github.com/getlantern/golog"
	"github.com/getlantern/netx"
)

const (
	maxUDPPacketSize = 512
)

var (
	log = golog.LoggerFor("dnsgrab")

	endianness = binary.BigEndian

	// We use Class-E network space for fake IPs, which gives us the ability to
	// have up to 268435454 addresses in-flight (much more than we can
	// realistically cache anyway). Class-E is reserved for research, so there
	// aren't any real Internet services listening on any of these addresses.
	minIP = ipStringToInt("240.0.0.1")       // begin of Class-E network
	maxIP = ipStringToInt("255.255.255.254") // end of Class-E network
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

	// ReverseLookup resolves the given fake IP address into the original hostname
	ReverseLookup(ip net.IP) string
}

type server struct {
	cacheSize        int
	defaultDNSServer string
	conn             *net.UDPConn
	client           *dns.Client
	ip               uint32
	namesByIP        map[uint32]*list.Element
	ipsByName        map[string]uint32
	ll               *list.List
	mx               sync.RWMutex
}

// Listen creates a new server listening at the given listenAddr and that
// forwards queries it can't handle to the given defaultDNSServer.
func Listen(cacheSize int, listenAddr string, defaultDNSServer string) (Server, error) {
	_, _, err := net.SplitHostPort(defaultDNSServer)
	if err != nil {
		defaultDNSServer = defaultDNSServer + ":53"
		log.Debugf("Defaulted port for defaultDNSServer to 53: %v", defaultDNSServer)
	}

	s := &server{
		cacheSize:        cacheSize,
		defaultDNSServer: defaultDNSServer,
		namesByIP:        make(map[uint32]*list.Element, cacheSize),
		ipsByName:        make(map[string]uint32, cacheSize),
		ll:               list.New(),
		client: &dns.Client{
			ReadTimeout: 2 * time.Second,
			Dial:        netx.DialTimeout,
		},
		ip: minIP,
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
			log.Error(err)
			continue
		}
		msgIn := &dns.Msg{}
		msgIn.Unpack(b[:n])
		go s.handle(remoteAddr, msgIn)
	}
}

func (s *server) Close() error {
	return s.conn.Close()
}

func (s *server) ReverseLookup(ip net.IP) string {
	ipInt := ipToInt(ip)
	s.mx.RLock()
	result, found := s.namesByIP[ipInt]
	s.mx.RUnlock()
	if !found {
		return ""
	}
	return result.Value.(string)
}

func (s *server) handle(remoteAddr *net.UDPAddr, msgIn *dns.Msg) {
	if len(msgIn.Question) == 0 {
		// TODO: forward the message upstream
	}

	msgOut := &dns.Msg{}
	msgOut.Response = true
	msgOut.Id = msgIn.Id
	msgOut.Question = msgIn.Question
	var unansweredQuestions []dns.Question
	for _, question := range msgIn.Question {
		if question.Qclass == dns.ClassINET && question.Qtype == dns.TypeA {
			answer := &dns.A{}
			// Short TTL should be fine since these DNS lookups are local and should be quite cheap
			answer.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}
			name := stripTrailingDot(question.Name)
			answerIP := net.ParseIP(name)
			if answerIP == nil {
				// Only map to fake IP if supplied wasn't an IP to begin with
				answerIP = s.mapToFakeIP(name)
			}
			answer.A = answerIP
			msgOut.Answer = append(msgOut.Answer, answer)
		} else {
			unansweredQuestions = append(unansweredQuestions, question)
		}
	}

	if len(unansweredQuestions) > 0 {
		msgIn.Question = unansweredQuestions
		resp, _, err := s.client.Exchange(msgIn, s.defaultDNSServer)
		if err != nil {
			log.Error(err)
		} else {
			msgOut.Answer = append(msgOut.Answer, resp.Answer...)
		}
	}

	bo, err := msgOut.Pack()
	if err != nil {
		log.Fatal(err)
	}
	_, writeErr := s.conn.WriteToUDP(bo, remoteAddr)
	if writeErr != nil {
		log.Errorf("Error responding to DNS query: %v", writeErr)
	}
}

func (s *server) mapToFakeIP(name string) net.IP {
	s.mx.Lock()
	ip, found := s.ipsByName[name]
	if found {
		e := s.namesByIP[ip]
		// move to front of LRU list
		s.ll.MoveToFront(e)
	} else {
		// get next fake IP from sequence
		ip = s.ip

		// insert to front of LRU list
		e := s.ll.PushFront(name)
		s.namesByIP[ip] = e
		s.ipsByName[name] = ip

		// remove oldest from LRU list if necessary
		if len(s.namesByIP) > s.cacheSize {
			oldestName := s.ll.Back().Value.(string)
			oldestIP := s.ipsByName[oldestName]
			delete(s.namesByIP, oldestIP)
			delete(s.ipsByName, oldestName)
		}

		// advance sequence
		s.ip++
		if s.ip > maxIP {
			// wrap IP to stay within allowed range
			s.ip = minIP
		}
	}
	fakeIP := make(net.IP, 4)
	endianness.PutUint32(fakeIP, ip)
	s.mx.Unlock()
	return fakeIP
}

func ipStringToInt(ip string) uint32 {
	return ipToInt(net.ParseIP(ip))
}

func ipToInt(ip net.IP) uint32 {
	return endianness.Uint32(ip.To4())
}

func intToIP(i uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	endianness.PutUint32(ip, i)
	return ip
}

func stripTrailingDot(name string) string {
	// strip trailing dot
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
