package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/transverse"
	"testing"
)

func TestDnsResolverAll(t *testing.T) {

	transverse.SetTest()

	tests := []struct {
		provider DnsResolverProvider
		name     string
		dnsType  uint16
		dnsSec   bool
	}{
		{NewDnsResolverGoogle, "gmail.com", dns.TypeSOA, false},
		{NewDnsResolverGoogle, "gmail.com", dns.TypeA, false},
		{NewDnsResolverGoogle, "gmail.com", dns.TypeMX, false},
		{NewDnsResolverGoogle, "gmail.com", dns.TypeTXT, false},
		{NewDnsResolverGoogle, "_dmarc.gmail.com", dns.TypeTXT, false},
		{NewDnsResolverGoogle, "icourrier.fr", dns.TypeSOA, true},
		{NewDnsResolverGoogle, "icourrier.fr", dns.TypeA, true},
		{NewDnsResolverGoogle, "icourrier.fr", dns.TypeMX, true},
		{NewDnsResolverGoogle, "icourrier.fr", dns.TypeTXT, true},
		{NewDnsResolverGoogle, "_dmarc.icourrier.fr", dns.TypeTXT, true},
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
