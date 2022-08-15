package main

import (
	"github.com/miekg/dns"
	"golang-dns/internal/providers"
	"golang-dns/internal/transverse"
	"log"
)

func main() {
	resolver := providers.NewGoogleDnsPool().WithCache().WithDnssec()

	rr, err := resolver.Query("_dmarc.icourrier.fr", dns.TypeTXT)
	if err != nil {
		log.Fatal(err)
	}

	transverse.Logger().Printf("%+v", rr)
}
