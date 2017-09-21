package dnsgrab

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
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
)

type Server interface {
	Serve() error

	Close() error

	ReverseLookup(ip net.IP) string
}

type server struct {
	defaultDNSServer string
	conn             *net.UDPConn
	client           *dns.Client
	idx              uint32
	domains          map[uint32]string
	mx               sync.RWMutex
}

func Listen(listenAddr string, defaultDNSServer string) (Server, error) {
	s := &server{
		defaultDNSServer: defaultDNSServer,
		domains:          make(map[uint32]string, 1000),
		client: &dns.Client{
			ReadTimeout: 2 * time.Second,
			Dial:        netx.DialTimeout,
		},
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
	ipInt := endianness.Uint32(ip)
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
			idx := atomic.AddUint32(&s.idx, 1)
			endianness.PutUint32(fakeIP, idx)
			answer.A = fakeIP
			msgOut.Answer = append(msgOut.Answer, answer)
			// Remember the query
			s.mx.Lock()
			s.domains[idx] = question.Name
			s.mx.Unlock()
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
