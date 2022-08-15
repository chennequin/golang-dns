package providers

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service"
	"golang-dns/internal/transverse"
	"testing"
)

func TestRestyAll(t *testing.T) {

	transverse.SetTest()

	pools := [][]DnsResolverParam{
		globalPool,
		googlePool,
		cloudFlarePool,
		quad9Pool,
	}

	for _, pool := range pools {
		for _, p := range pool {
			resolver := service.NewDnsResolverRestyImpl(service.NewHardenedResty(p.ServerName, p.CertFile, p.ip), p.Url).WithDnssec()
			resp, err := resolver.Query("dns.google", dns.TypeA)
			expectNoErr(t, err)
			if len(resp.GetRR()) == 0 {
				t.Fatalf("got empty response %v", resp)
			}
		}
	}

	t.Logf("Success !")
}

func expectNoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("got error %v", err.Error())
	}
}
