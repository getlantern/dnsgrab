package dnsgrab

import (
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

	minIP = ipStringToInt("240.0.0.1")       // Class-E network (reserved for research)
	maxIP = ipStringToInt("255.255.255.254") // end of Class-E network
)

// Server is a dns server that resolves queries for A records into fake IP
// addresses within the Class-E address space and allows reverse resolution of
// those back into the originally queried hostname.
type Server interface {
	// Serve() runs the server (blocks until server ends)
	Serve() error

	// Close closes the server's network listener.
	Close() error

	// ReverseLookup resolves the given fake IP address into the original hostname
	ReverseLookup(ip net.IP) string
}

type server struct {
	defaultDNSServer string
	conn             *net.UDPConn
	client           *dns.Client
	ip               uint32
	domains          map[uint32]string
	mx               sync.RWMutex
}

// Listen creates a new server listening at the given listenAddr and that
// forwards queries it can't handle to the given defaultDNSServer.
func Listen(listenAddr string, defaultDNSServer string) (Server, error) {
	s := &server{
		defaultDNSServer: defaultDNSServer,
		domains:          make(map[uint32]string, 1000),
		client: &dns.Client{
			ReadTimeout: 2 * time.Second,
			Dial:        netx.DialTimeout,
		},
		ip: minIP,
	}

	// TODO: clear out domains after TTL
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
		log.Debugf("Got Message\n------------------------------\n%v\n------------------------------", msgIn)
		go s.handle(remoteAddr, msgIn)
	}
}

func (s *server) Close() error {
	return s.conn.Close()
}

func (s *server) ReverseLookup(ip net.IP) string {
	ipInt := ipToInt(ip)
	s.mx.RLock()
	result := s.domains[ipInt]
	s.mx.RUnlock()
	return result
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
			fakeIP := make(net.IP, 4)
			s.mx.Lock()
			endianness.PutUint32(fakeIP, s.ip)
			// Remember the query
			s.domains[s.ip] = question.Name
			s.ip++
			if s.ip > maxIP {
				// wrap IP to stay within allowed range
				log.Debug("Wrapping")
				s.ip = minIP
			}
			s.mx.Unlock()
			answer.A = fakeIP
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
	s.conn.WriteToUDP(bo, remoteAddr)
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
