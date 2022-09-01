package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service/conf"
	"net"
	"testing"
)

func NewDnsPoolResolver() DnsResolverProxy {
	return NewDnsResolverPoolImpl(
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/dns-query"),
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 4, 4)), "https://8.8.4.4/dns-query"),
	)
}

func NewErroneousDnsPoolResolver() DnsResolverProxy {
	return NewDnsResolverPoolImpl(
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/erroneous"),
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 4, 4)), "https://8.8.4.4/dns-query"),
	)
}

func NewMalFunctioningDnsPoolResolver() DnsResolverProxy {
	return NewDnsResolverPoolImpl(
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/erroneous"),
		NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 4, 4)), "https://8.8.4.4/erroneous"),
	)
}

func TestDnsPool(t *testing.T) {

	r := NewDnsPoolResolver().AsResolver()

	_, err := r.Query("afnic.fr", dns.TypeA)
	if err != nil {
		t.Fatalf("error: %s", err.Error())
	}

	t.Logf("Success !")
}

func TestDnsPoolResilience(t *testing.T) {

	r := NewErroneousDnsPoolResolver().AsResolver()

	_, err := r.Query("afnic.fr", dns.TypeA)
	if err != nil {
		t.Fatalf("error: %s", err.Error())
	}

	t.Logf("Success !")
}

func TestDnsPoolError(t *testing.T) {

	r := NewMalFunctioningDnsPoolResolver().AsResolver()

	_, err := r.Query("afnic.fr", dns.TypeA)
	if err == nil {
		t.Fatalf("must receive error")
	}

	t.Logf("received error: %s", err)
	t.Logf("Success !")
}
