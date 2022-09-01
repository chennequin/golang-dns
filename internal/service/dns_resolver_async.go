package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type AsyncDnsResolver interface {
	Query(name string, dnsType uint16) model.AsyncDnsMsg
}

type AsyncDnsResolverImpl struct {
	DnsResolverProxyBase
	resolver DnsResolverProxy
}

func NewAsyncDnsResolverImpl(resolver DnsResolverProxy) AsyncDnsResolver {
	var r AsyncDnsResolverImpl
	defer transverse.Logger().Printf("%s initialized", &r)
	r.resolver = resolver
	return r
}

func (s AsyncDnsResolverImpl) Query(name string, dnsType uint16) model.AsyncDnsMsg {
	async := model.NewAsyncDnsMsg()
	go func() {
		m := model.NewDnsMsg(h.Msg(name, dnsType, dns.ClassINET))
		query, err := s.resolver.Proxy(m)
		async.Push(query, err)
	}()
	return async
}

func (s AsyncDnsResolverImpl) String() string {
	return fmt.Sprintf("AsyncDnsResolverImpl %s", s.resolver)
}
