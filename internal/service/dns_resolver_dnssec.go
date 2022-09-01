package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnssecResolver struct {
	DnsResolverProxyBase
	resolver  DnsResolverProxy
	validator DnssecValidator
}

func NewDnssecResolver(resolver DnsResolverProxy, validator DnssecValidator) DnsResolverProxy {
	var rsv DnssecResolver
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolver = resolver
	rsv.validator = validator
	return &rsv
}

func (rsv DnssecResolver) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	in, err := rsv.resolver.Proxy(rm)
	if err != nil {
		return in, err
	}

	if in.IsRRSIG() {
		err = rsv.validator.Verify(in)
		return in, err
	}

	return in, nil
}

func (_ DnssecResolver) String() string {
	return fmt.Sprintf("DnssecResolver")
}
