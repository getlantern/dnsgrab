package dnsgrab

import (
	"net"
	"strings"
	"testing"

	"github.com/getlantern/dns"
	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	s, err := Listen(2, ":0", "8.8.8.8")
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	addr := s.LocalAddr().String()

	test := func(name string, expectedIP string, condition string) {
		q := &dns.Msg{}
		q.SetQuestion(name+".", dns.TypeA)

		a, err := dns.Exchange(q, addr)
		if !assert.NoError(t, err) {
			return
		}

		fakeIP := a.Answer[0].(*dns.A).A
		assert.Equal(t, expectedIP, fakeIP.String(), "Wrong IP from query for '%v'", condition)

		q = makeSRPQuery(expectedIP)
		parts := strings.Split(expectedIP, ".")
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
		q.SetQuestion(ipQuery, dns.TypePTR)

		a, err = dns.Exchange(q, addr)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, name+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup for '%v'", condition)
		assert.Equal(t, name, s.ReverseLookup(fakeIP))
	}

	test("domain1", "240.0.0.1", "first query, new IP")
	test("domain2", "240.0.0.2", "second query, new IP")
	test("domain1", "240.0.0.1", "repeated query, same IP")
	test("domain3", "240.0.0.3", "third query, new IP")
	test("domain4", "240.0.0.4", "repeated expired query, new IP")

	// Also test that SRP lookups for unknown IPs get passed through
	host := "dfw28s05-in-f4.1e100.net"
	ip, err := net.ResolveIPAddr("ip4", host)
	if !assert.NoError(t, err) {
		return
	}

	q := makeSRPQuery(ip.String())
	a, err := dns.Exchange(q, addr)
	if !assert.NoError(t, err) {
		return
	}
	if assert.Len(t, a.Answer, 1) {
		assert.Equal(t, host+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup of %v", host)
	}
}

func makeSRPQuery(ip string) *dns.Msg {
	q := &dns.Msg{}
	parts := strings.Split(ip, ".")
	parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
	ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
	q.SetQuestion(ipQuery, dns.TypePTR)
	return q
}
