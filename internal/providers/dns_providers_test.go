package providers

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service"
	"golang-dns/internal/transverse"
	"testing"
)

func TestProvidersAll(t *testing.T) {

	transverse.SetTest()

	pools := [][]DnsResolverParam{
		globalPool,
		googlePool,
		cloudFlarePool,
		quad9Pool,
	}

	for _, pool := range pools {
		for _, p := range pool {

			resolver := service.NewDnsResolverRestyImpl(service.NewHardenedResty(p.ServerName, p.CertFile, p.ip), p.Url).WithDnssec().AsResolver()
			resp, err := resolver.Query("dns.google", dns.TypeA)

			expectNoErr(t, err)
			if len(resp.GetRR()) == 0 {
				t.Fatalf("got empty response %v", resp)
			}

			if !resp.IsRRSIG() {
				t.Fatalf("response should be signed with dnssec")
			}

			if len(resp.GetRR()) != 2 {
				t.Fatalf("got wrong response %v", resp)
			}

			a := resp.GetRR()[0].(*dns.A).A.String()
			b := resp.GetRR()[1].(*dns.A).A.String()

			if a == "8.8.8.8" {
				if b != "8.8.4.4" {
					t.Fatalf("got wrong response %v", resp)
				}
				continue
			}

			if a == "8.8.4.4" {
				if b != "8.8.8.8" {
					t.Fatalf("got wrong response %v", resp)
				}
				continue
			}

			t.Fatalf("wrong response %v", resp)
		}
	}

	t.Logf("Success !")
}

func expectNoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("got error: %v", err.Error())
	}
}
