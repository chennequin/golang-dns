package service

import (
	"fmt"
	h "golang-dns/internal/helpers"
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

func (rsv DnssecResolverEnforced) Query(name string, dnsType uint16) (model.DnsMsg, error) {
	rm := model.NewDnsMsg(h.Msg(name, dnsType))
	return rsv.Proxy(rm)
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
