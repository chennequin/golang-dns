package main

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service"
	"golang-dns/internal/service/model"
	"golang-dns/internal/transverse"
	"log"
)

func main() {
	resolver := service.NewDnsResolverGoogle()
	cache := service.NewDnsCache(resolver)
	validator := service.NewDnssecValidator(cache, model.LoadTrustAnchors())
	facade := service.NewDnsFacade(cache, validator)

	rr, err := facade.Query("_dmarc.icourrier.fr", dns.TypeTXT)
	if err != nil {
		log.Fatal(err)
	}

	transverse.Logger().Printf("%+v", rr)
}
