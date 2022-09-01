package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsResolverImpl struct {
	resolver DnsResolverProxy
}

func NewDnsResolverImpl(resolver DnsResolverProxy) DnsResolver {
	var rsv DnsResolverImpl
	defer transverse.Logger().Printf("%s initialized", &rsv)
	rsv.resolver = resolver
	return rsv
}

func (rsv DnsResolverImpl) Query(name string, dnsType uint16) (model.DnsMsg, error) {

	if _, valid := dns.IsDomainName(name); !valid {
		return model.DnsMsg{}, fmt.Errorf("must provide a valid domain name")
	}

	rm := model.NewDnsMsg(h.Msg(name, dnsType, dns.ClassINET))
	in, err := rsv.resolver.Proxy(rm)
	return in, err
}

func (rsv DnsResolverImpl) String() string {
	return fmt.Sprintf("DnsResolverImpl")
}
