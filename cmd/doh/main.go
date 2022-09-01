package main

import (
	"github.com/miekg/dns"
	"golang-dns/internal/providers"
	"golang-dns/internal/transverse"
	"log"
)

func main() {
	resolver := providers.NewQuad9DnsPool().WithLog().WithCache().WithDnssec().WithRateLimiting().AsResolver()

	rr, err := resolver.Query("dns.google.", dns.TypeA)
	if err != nil {
		log.Fatal(err)
	}

	transverse.Logger().Printf("%+v", rr)
}
