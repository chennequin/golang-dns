package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsResolverPoolImpl struct {
	DnsResolverBase
	resolvers []DnsResolver
}

func NewDnsResolverPoolImpl(resolvers ...DnsResolver) DnsResolver {
	var rsv DnsResolverPoolImpl
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolvers = resolvers
	return &rsv
}

func (rsv DnsResolverPoolImpl) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	accErrors := ""

	for _, r := range rsv.resolvers {
		if query, err := r.Query(name, dnsType); err == nil {
			return query, nil
		} else {
			accErrors = fmt.Sprintf("[%s] %s", err.Error(), accErrors)
		}
	}

	return model.DnsResponse{}, fmt.Errorf("all resolvers returned error: %s", accErrors)
}

func (rsv DnsResolverPoolImpl) String() string {
	return fmt.Sprintf("DnsResolverPoolImpl %s", rsv.resolvers)
}
