package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
	"testing"
)

var FakeAnchor = dns.DNSKEY{
	Flags:     257,
	Protocol:  3,
	Algorithm: 8,
	PublicKey: conf.TrimAll(
		`BwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
			+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv
			ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF
			0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e
			oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd
			RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN
			R1AkUTV74bU=`),
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
		{"_dmarc.icourrier.fr", dns.TypeTXT},
	}

	resolver := NewDnsResolverGoogle()
	validator := NewDnssecValidator(resolver, conf.TrustAnchor)

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

		err = validator.VerifySig(r)
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
	validator := NewDnssecValidator(resolver, FakeAnchor)

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

		err = validator.VerifySig(r)
		if err == nil {
			t.Fatalf("not received any error")
		}

		t.Logf("received error: %v", err.Error())
	}

	t.Logf("Success !")
}
