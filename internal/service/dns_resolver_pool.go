package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsResolverPoolImpl struct {
	DnsResolverProxyBase
	resolvers []DnsResolverProxy
}

func NewDnsResolverPoolImpl(resolvers ...DnsResolverProxy) DnsResolverProxy {
	var rsv DnsResolverPoolImpl
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolvers = resolvers
	return &rsv
}

func (rsv DnsResolverPoolImpl) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	accErrors := ""

	for _, r := range rsv.resolvers {
		if nrm, err := r.Proxy(rm); err == nil {
			return nrm, nil
		} else {
			accErrors = fmt.Sprintf("[%s] %s", err.Error(), accErrors)
		}
	}

	return rm, fmt.Errorf("all resolvers returned error: %s", accErrors)
}

func (rsv DnsResolverPoolImpl) String() string {
	return fmt.Sprintf("DnsResolverPoolImpl %s", rsv.resolvers)
}
