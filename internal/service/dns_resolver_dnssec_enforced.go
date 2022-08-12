package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnssecResolverEnforced struct {
	DnsResolverBase
	resolver  DnsResolver
	validator DnssecValidator
}

func NewDnssecResolverEnforced(resolver DnsResolver, validator DnssecValidator) DnssecResolverEnforced {
	var rsv DnssecResolverEnforced
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolver = resolver
	rsv.validator = validator
	return rsv
}

func (rsv DnssecResolverEnforced) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	r, err := rsv.resolver.Query(name, dnsType)
	if err != nil {
		return r, err
	}

	if !r.IsRRSIG() {
		return r, fmt.Errorf("no dnssec signature")
	}

	err = rsv.validator.Verify(r)
	return r, err
}

func (_ DnssecResolverEnforced) String() string {
	return fmt.Sprintf("DnssecResolverEnforced")
}
