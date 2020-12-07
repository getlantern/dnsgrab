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
	"github.com/getlantern/dnsgrab/common"
	"github.com/getlantern/dnsgrab/persistentcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemory(t *testing.T) {
	doTest(t, NewInMemoryCache(2), common.MinIP)
}

func TestPersistent(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "dnsgrab")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	filename := filepath.Join(tmpDir, "dnsgrab.db")
	cache, err := persistentcache.New(filename, 250*time.Millisecond)
	require.NoError(t, err)
	doTest(t, cache, common.MinIP)
	cache.Close()

	// Reopen cache and test again to make sure that initialization of already saved DB is handled correctly
	time.Sleep(500 * time.Millisecond)
	reopenedCache, err := persistentcache.New(filename, 250*time.Millisecond)
	require.NoError(t, err)
	doTest(t, reopenedCache, common.IPStringToInt("240.0.0.5"))
}

func doTest(t *testing.T, cache Cache, startingIP uint32) {
	s, err := ListenWithCache(":0", "8.8.8.8", cache)
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	addr := s.LocalAddr().String()

	test := func(name string, expectedIPInt uint32, condition string) {
		expectedIP := common.IntToIP(expectedIPInt).String()
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
		assert.Equal(t, name, s.ReverseLookup(fakeIP))
	}

	test("domain1", startingIP, "first query, new IP")
	time.Sleep(15 * time.Millisecond)
	test("domain2", startingIP+1, "second query, new IP")
	time.Sleep(15 * time.Millisecond)
	test("domain1", startingIP, "repeated query, same IP")
	time.Sleep(15 * time.Millisecond)
	test("domain3", startingIP+2, "third query, new IP")
	time.Sleep(500 * time.Millisecond)
	test("domain2", startingIP+3, "repeated expired query, new IP")

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
