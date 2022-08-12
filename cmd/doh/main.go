package main

import (
	"github.com/miekg/dns"
	"golang-dns/internal/providers"
	"golang-dns/internal/service"
	"golang-dns/internal/transverse"
	"log"
)

func main() {
	resolver := providers.NewDnsResolverGoogle()
	cache := service.NewDnsCache(resolver)
	validator := service.NewDnssecValidator(cache)
	facade := service.NewDnssecResolver(cache, validator)

	rr, err := facade.Query("_dmarc.icourrier.fr", dns.TypeTXT)
	if err != nil {
		log.Fatal(err)
	}

	transverse.Logger().Printf("%+v", rr)
}
