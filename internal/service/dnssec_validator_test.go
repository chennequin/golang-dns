package service

import (
	_ "embed"
	"github.com/miekg/dns"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
	"net"
	"testing"
)

//go:embed conf/dns/fake-anchors.xml
var FakeAnchorsFile string

func NewDnsSecResolver() DnsResolverProxy {
	return NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/dns-query")
}

func TestDnssecValid(t *testing.T) {

	transverse.SetTest()

	tests := []struct {
		name    string
		dnsType uint16
	}{
		{"afnic.fr", dns.TypeSOA},
		{"afnic.fr", dns.TypeA},
		{"afnic.fr", dns.TypeMX},
		{"afnic.fr", dns.TypeTXT},
		{"icourrier.fr", dns.TypeMX},
		{"_dmarc.icourrier.fr", dns.TypeTXT},
		{"chrome.cloudflare-dns.com.", dns.TypeA},
		{"protonvpn.ch.", dns.TypeA},
		{"client.dropbox.com.", dns.TypeA},
		{"api.dropboxapi.com.", dns.TypeA},
	}

	proxy := NewDnsSecResolver()
	validator := NewDnssecValidator(proxy)
	resolver := proxy.AsResolver()

	for _, tt := range tests {
		r, err := resolver.Query(tt.name, tt.dnsType)
		if err != nil {
			t.Fatalf("received error: %v", err.Error())
		}
		if len(r.GetRR()) < 1 {
			t.Fatalf("RR not present")
		}
		if r.GetRRSIG() == nil {
			t.Fatalf("RRSIG not present")
		}

		err = validator.Verify(r)
		if err != nil {
			t.Fatalf("received error: %v", err.Error())
		}

		t.Logf("received %v", r.GetMsg().Answer)
	}

	t.Logf("Success !")
}

func TestDnssecInvalid(t *testing.T) {

	transverse.SetTest()

	tests := []struct {
		name    string
		dnsType uint16
	}{
		{"afnic.fr", dns.TypeSOA},
		{"afnic.fr", dns.TypeA},
		{"afnic.fr", dns.TypeMX},
		{"afnic.fr", dns.TypeTXT},
	}

	proxy := NewDnsSecResolver()
	validator := NewDnssecValidatorFromIanaFile(proxy, LoadIanaFile(FakeAnchorsFile)) // fake anchors
	resolver := proxy.AsResolver()

	for _, tt := range tests {
		r, err := resolver.Query(tt.name, tt.dnsType)
		if err != nil {
			t.Fatalf("received error: %v", err.Error())
		}
		if len(r.GetRR()) < 1 {
			t.Fatalf("RR not present")
		}
		if r.GetRRSIG() == nil {
			t.Fatalf("RRSIG not present")
		}

		err = validator.Verify(r)
		if err == nil {
			t.Fatalf("not received any error")
		}

		t.Logf("received error: %v", err.Error())
	}

	t.Logf("Success !")
}
