package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type AsyncDnsResolver interface {
	Query(name string, dnsType uint16) model.AsyncDnsResponse
}

type AsyncDnsResolverImpl struct {
	resolver DnsResolver
}

func NewAsyncDnsResolverImpl(resolver DnsResolver) AsyncDnsResolver {
	var r AsyncDnsResolverImpl
	defer transverse.Logger().Printf("%s initialized", &r)
	r.resolver = resolver
	return r
}

func (s AsyncDnsResolverImpl) Query(name string, dnsType uint16) model.AsyncDnsResponse {
	async := model.NewAsyncDnsResponse()
	go func() {
		async.Push(s.resolver.Query(name, dnsType))
	}()
	return async
}

func (s AsyncDnsResolverImpl) String() string {
	return fmt.Sprintf("AsyncDnsResolverImpl %s", s.resolver)
}
