package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnssecResolver struct {
	DnsResolverBase
	resolver  DnsResolver
	validator DnssecValidator
}

func NewDnssecResolver(resolver DnsResolver, validator DnssecValidator) DnssecResolver {
	var rsv DnssecResolver
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolver = resolver
	rsv.validator = validator
	return rsv
}

func (f DnssecResolver) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	r, err := f.resolver.Query(name, dnsType)
	if err != nil {
		return r, err
	}

	if r.IsRRSIG() {
		err = f.validator.Verify(r)
		return r, err
	}

	return r, nil
}

func (_ DnssecResolver) String() string {
	return fmt.Sprintf("DnssecResolver")
}
