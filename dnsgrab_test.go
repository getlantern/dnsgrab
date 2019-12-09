package dnsgrab

import (
	"fmt"
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

		assert.Equal(t, fmt.Sprintf("%s.	1	IN	A	%s", name, expectedIP), a.Answer[0].String(), "Wrong IP from query for '%v'", condition)

		q = &dns.Msg{}
		parts := strings.Split(expectedIP, ".")
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		ipQuery := strings.Join(parts, ".") + ".in-addr.arpa."
		q.SetQuestion(ipQuery, dns.TypePTR)

		a, err = dns.Exchange(q, addr)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, name+".", a.Answer[0].(*dns.PTR).Ptr, "Wrong name from reverse lookup for '%v'", condition)
	}

	test("domain1", "240.0.0.1", "first query, new IP")
	test("domain2", "240.0.0.2", "second query, new IP")
	test("domain1", "240.0.0.1", "repeated query, same IP")
	test("domain3", "240.0.0.3", "third query, new IP")
	test("domain4", "240.0.0.4", "repeated expired query, new IP")
}
