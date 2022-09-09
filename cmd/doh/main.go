package main

import (
	"github.com/miekg/dns"
	"golang-dns/internal/providers"
	"golang-dns/internal/transverse"
	"log"
)

func main() {
	resolver := providers.NewGoogleDnsPool().WithCache().WithDnssec().WithLog().WithRateLimiting().AsResolver()

	rr, err := resolver.Query("ocsp.pki.goog.", dns.TypeA)
	if err != nil {
		log.Fatal(err)
	}

	transverse.Logger().Printf("%+v", rr)

}
