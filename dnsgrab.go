package main

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/getlantern/golog"
	"github.com/miekg/dns"
)

const (
	maxUDPPacketSize = 512
)

var (
	log = golog.LoggerFor("dnsgrab")

	bigEndian = binary.BigEndian

	// TODO: clear out domains after TTL
	domains = make(map[uint32]string, 1000)
	mx      sync.RWMutex
)

func main() {
	go debugQueries()

	addr, err := net.ResolveUDPAddr("udp", ":55899")
	if err != nil {
		log.Fatal(err)
	}
	in, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()
	log.Debugf("Listening at: %v", in.LocalAddr())

	b := make([]byte, maxUDPPacketSize)
	idx := uint32(0)
	for {
		n, remoteAddr, err := in.ReadFromUDP(b)
		if err != nil {
			log.Fatal(err)
		}
		msgIn := &dns.Msg{}
		msgIn.Unpack(b[:n])
		if len(msgIn.Question) == 0 {
			// TODO: forward the message upstream
		}
		msgOut := &dns.Msg{}
		msgOut.Response = true
		msgOut.Id = msgIn.Id
		msgOut.Question = msgIn.Question
		for _, question := range msgIn.Question {
			if question.Qclass == dns.ClassINET && question.Qtype == dns.TypeA {
				answer := &dns.A{}
				// Short TTL should be fine since these DNS lookups are local and should be quite cheap
				answer.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}
				fakeIP := make(net.IP, 4)
				bigEndian.PutUint32(fakeIP, idx)
				answer.A = fakeIP
				msgOut.Answer = append(msgOut.Answer, answer)
				// Remember the query
				mx.Lock()
				domains[idx] = question.Name
				mx.Unlock()
				idx++
			} else {
				// TODO: resolve upstream
			}
		}

		bo, err := msgOut.Pack()
		if err != nil {
			log.Fatal(err)
		}
		in.WriteToUDP(bo, remoteAddr)
	}
}

func debugQueries() {
	for {
		time.Sleep(1 * time.Second)
		mx.RLock()
		for id, name := range domains {
			log.Debugf("%d -> %v", id, name)
		}
		mx.RUnlock()
	}
}
