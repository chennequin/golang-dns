package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/transverse"
	"testing"
)

func TestDnsResolverAll(t *testing.T) {

	transverse.SetTest()

	tests := []struct {
		provider func() DnsResolver
		name     string
		dnsType  uint16
		dnsSec   bool
	}{
		{NewDnsResolver, "gmail.com", dns.TypeSOA, false},
		{NewDnsResolver, "gmail.com", dns.TypeA, false},
		{NewDnsResolver, "gmail.com", dns.TypeMX, false},
		{NewDnsResolver, "gmail.com", dns.TypeTXT, false},
		{NewDnsResolver, "_dmarc.gmail.com", dns.TypeTXT, false},
		{NewDnsResolver, "icourrier.fr", dns.TypeSOA, true},
		{NewDnsResolver, "icourrier.fr", dns.TypeA, true},
		{NewDnsResolver, "icourrier.fr", dns.TypeMX, true},
		{NewDnsResolver, "icourrier.fr", dns.TypeTXT, true},
		{NewDnsResolver, "_dmarc.icourrier.fr", dns.TypeTXT, true},
	}

	for _, tt := range tests {
		r := tt.provider()
		m, err := r.Query(tt.name, tt.dnsType)
		if err != nil {
			t.Fatalf("received error: %v", err.Error())
		}
		if tt.dnsSec {
			if !m.IsRRSIG() {
				t.Fatalf("RRSIG not present")
			}
		}
		if len(m.GetRR()) < 1 {
			t.Fatalf("RRS not present")
		}
		t.Logf("received %v", m.GetRR())
	}

	t.Logf("Success !")
}
