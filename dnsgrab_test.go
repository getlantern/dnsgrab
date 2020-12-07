package dnsgrab

import (
	"net"
	"strings"
	"testing"

	"github.com/getlantern/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemory(t *testing.T) {
	doTest(t, NewInMemoryCache(2))
}

func doTest(t *testing.T, cache Cache) {
	s, err := ListenWithCache(":0", "8.8.8.8", cache)
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

		q = makeSRPQuery(fakeIP.String())
		parts := strings.Split(fakeIP.String(), ".")
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
		q.SetQuestion(ipQuery, dns.TypePTR)

		a, err = dns.Exchange(q, addr)
		if !assert.NoError(t, err) {
			return
		}
		log.Debugf("Num answers: %d", len(a.Answer))
		assert.Equal(t, name+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup for '%v'", condition)
		reversed, ok := s.ReverseLookup(fakeIP)
		require.True(t, ok, "Reverse lookup failed for '%v'", condition)
		assert.Equal(t, name, reversed, "Wrong reverse lookup for '%v'", condition)
	}

	testUnknown := func(name string, succeed bool, ip string, condition string) {
		reversed, ok := s.ReverseLookup(net.ParseIP(ip))
		require.Equal(t, succeed, ok, "Unexpected reverse lookup status for '%v'", condition)
		assert.Equal(t, name, reversed, "Wrong reverse lookup for '%v'", condition)
	}

	test("domain1", "240.0.0.1", "first query, new IP")
	test("domain2", "240.0.0.2", "second query, new IP")
	test("domain1", "240.0.0.1", "repeated query, same IP")
	test("domain3", "240.0.0.3", "third query, new IP")
	test("domain2", "240.0.0.4", "repeated expired query, new IP")

	testUnknown("172.155.98.32", true, "172.155.98.32", "regular IP address")
	testUnknown("", false, "240.0.10.10", "unknown fake IP address")

	// Also test that SRP lookups for unknown IPs get passed through
	host := "dfw28s05-in-f4.1e100.net"
	ip, err := net.ResolveIPAddr("ip4", host)
	require.NoError(t, err)

	q := makeSRPQuery(ip.String())
	a, err := dns.Exchange(q, addr)
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
	require.Equal(t, host+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup of %v", host)
}

func makeSRPQuery(ip string) *dns.Msg {
	q := &dns.Msg{}
	parts := strings.Split(ip, ".")
	parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
	ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
	q.SetQuestion(ipQuery, dns.TypePTR)
	return q
}
