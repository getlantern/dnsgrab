package dnsgrab

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/dns"
	"github.com/getlantern/dnsgrab/boltcache"
	"github.com/getlantern/dnsgrab/internal"
	"github.com/stretchr/testify/require"
)

const (
	maxAge = 2 * time.Second
)

func testInMemory(t *testing.T) {
	doTest(t, internal.NewInMemoryCache(2), internal.MinIP)
}

func TestBolt(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "dnsgrab")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "dnsgrab.db")
	cache, err := boltcache.New(filename, maxAge)
	require.NoError(t, err)
	doTest(t, cache, internal.MinIP)
	cache.Close()

	// Reopen cache and test again to make sure that initialization of already saved DB is handled correctly
	time.Sleep(maxAge)
	reopenedCache, err := boltcache.New(filename, maxAge)
	require.NoError(t, err)
	doTest(t, reopenedCache, internal.IPStringToInt("240.0.0.5"))
	cache.Close()
}

func doTest(t *testing.T, cache internal.Cache, startingIP uint32) {
	s, err := ListenWithCache(":0", "8.8.8.8", cache)
	require.NoError(t, err)
	defer s.Close()
	go s.Serve()

	addr := s.LocalAddr().String()

	test := func(name string, expectedIPInt uint32, condition string) {
		expectedIP := internal.IntToIP(expectedIPInt).String()
		q := &dns.Msg{}
		q.SetQuestion(name+".", dns.TypeA)

		a, err := dns.Exchange(q, addr)
		require.NoError(t, err)

		fakeIP := a.Answer[0].(*dns.A).A
		require.Equal(t, expectedIP, fakeIP.String(), "Wrong IP from query for '%v'", condition)

		q = makeSRPQuery(fakeIP.String())
		parts := strings.Split(fakeIP.String(), ".")
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
		q.SetQuestion(ipQuery, dns.TypePTR)

		a, err = dns.Exchange(q, addr)
		require.NoError(t, err)
		require.Len(t, a.Answer, 1)
		require.Equal(t, name+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup for '%v'", condition)
		reversed, ok := s.ReverseLookup(fakeIP)
		require.True(t, ok, "Reverse lookup failed for '%v'", condition)
		require.Equal(t, name, reversed, "Wrong reverse lookup for '%v'", condition)
	}

	testUnknown := func(name string, succeed bool, ip string, condition string) {
		reversed, ok := s.ReverseLookup(net.ParseIP(ip))
		require.Equal(t, succeed, ok, "Unexpected reverse lookup status for '%v'", condition)
		require.Equal(t, name, reversed, "Wrong reverse lookup for '%v'", condition)
	}

	test("domain1", startingIP, "first query, new IP")
	test("domain2", startingIP+1, "second query, new IP")
	test("domain1", startingIP, "repeated query, same IP")
	test("domain3", startingIP+2, "third query, new IP")
	time.Sleep(maxAge)
	test("domain2", startingIP+3, "repeated expired query, new IP")

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
