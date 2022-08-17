package service

import (
	"fmt"
	h "golang-dns/internal/helpers"
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

func (rsv DnsResolverPoolImpl) Query(name string, dnsType uint16) (model.DnsMsg, error) {
	rm := model.NewDnsMsg(h.Msg(name, dnsType))
	return rsv.Proxy(rm)
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
