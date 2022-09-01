package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnssecResolverEnforced struct {
	DnsResolverProxyBase
	resolver  DnsResolverProxy
	validator DnssecValidator
}

func NewDnssecResolverEnforced(resolver DnsResolverProxy, validator DnssecValidator) DnssecResolverEnforced {
	var rsv DnssecResolverEnforced
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolver = resolver
	rsv.validator = validator
	return rsv
}

func (rsv DnssecResolverEnforced) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	in, err := rsv.resolver.Proxy(rm)
	if err != nil {
		return in, err
	}

	if !in.IsRRSIG() {
		return in, fmt.Errorf("no dnssec signature")
	}

	err = rsv.validator.Verify(in)
	return in, err
}

func (_ DnssecResolverEnforced) String() string {
	return fmt.Sprintf("DnssecResolverEnforced")
}
