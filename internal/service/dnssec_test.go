package service

import (
	_ "embed"
	"github.com/miekg/dns"
	"golang-dns/internal/service/model"
	"golang-dns/internal/transverse"
	"testing"
)

//go:embed conf/dns/fake-anchors.xml
var FakeAnchorsFile string

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
		{"_dmarc.icourrier.fr", dns.TypeTXT},
	}

	resolver := NewDnsResolverGoogle()
	validator := NewDnssecValidator(resolver, model.LoadTrustAnchors())

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

	resolver := NewDnsResolverGoogle()
	validator := NewDnssecValidator(resolver, model.LoadTrustAnchorFromFile(FakeAnchorsFile))

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
