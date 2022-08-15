package service

import "golang-dns/internal/model"

type DnsResolver interface {
	Query(name string, dnsType uint16) (model.DnsResponse, error)
	AsAsync() AsyncDnsResolver
	WithCache() DnsResolver
	WithDnssec() DnsResolver
}

type DnsResolverBase struct {
	resolver DnsResolver
}

func (s *DnsResolverBase) initDnsResolverBase(resolver DnsResolver) {
	s.resolver = resolver
}

func (s *DnsResolverBase) AsAsync() AsyncDnsResolver {
	return NewAsyncDnsResolverImpl(s.resolver)
}

func (s *DnsResolverBase) WithCache() DnsResolver {
	return NewDnsCache(s.resolver)
}

func (s *DnsResolverBase) WithDnssec() DnsResolver {
	return NewDnssecResolver(s.resolver, NewDnssecValidator(s.resolver))
}
