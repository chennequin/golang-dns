package service

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service/conf"
	"net"
	"testing"
)

func NewAsyncDnsResolver() AsyncDnsResolver {
	return NewAsyncDnsResolverImpl(NewDnsResolverRestyImpl(NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)), "https://8.8.8.8/dns-query"))

}

func TestAsyncResolver(t *testing.T) {

	r := NewAsyncDnsResolver()

	resp, err := r.Query("afnic.fr", dns.TypeA).Result()
	if err != nil {
		t.Fatalf("error: %s", err.Error())
	}

	t.Logf("received %s", resp)
	t.Logf("Success !")
}
