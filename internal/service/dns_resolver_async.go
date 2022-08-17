package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type AsyncDnsResolver interface {
	Query(name string, dnsType uint16) model.AsyncDnsMsg
}

type AsyncDnsResolverImpl struct {
	DnsResolverBase
	resolver DnsResolver
}

func NewAsyncDnsResolverImpl(resolver DnsResolver) AsyncDnsResolver {
	var r AsyncDnsResolverImpl
	defer transverse.Logger().Printf("%s initialized", &r)
	r.resolver = resolver
	return r
}

func (s AsyncDnsResolverImpl) Query(name string, dnsType uint16) model.AsyncDnsMsg {
	async := model.NewAsyncDnsMsg()
	go func() {
		query, err := s.resolver.Query(name, dnsType)
		async.Push(query, err)
	}()
	return async
}

func (s AsyncDnsResolverImpl) String() string {
	return fmt.Sprintf("AsyncDnsResolverImpl %s", s.resolver)
}
