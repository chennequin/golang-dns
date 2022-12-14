package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
	"net"
	"testing"
)

func NewDnsResolver() DnsResolverProxy {
	return NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/dns-query")
}

func TestDnsResolverAll(t *testing.T) {

	transverse.SetTest()

	tests := []struct {
		provider func() DnsResolverProxy
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
		r := tt.provider().AsResolver()
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
