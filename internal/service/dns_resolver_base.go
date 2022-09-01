package service

import (
	"golang-dns/internal/model"
)

type DnsResolver interface {
	Query(name string, dnsType uint16) (model.DnsMsg, error)
}

type DnsResolverProxy interface {
	Proxy(_ model.DnsMsg) (model.DnsMsg, error)
	AsAsync() AsyncDnsResolver
	AsResolver() DnsResolver
	WithCache() DnsResolverProxy
	WithDnssec() DnsResolverProxy
	WithBadger() DnsResolverProxy
	WithLog() DnsResolverProxy
	WithRateLimiting() DnsResolverProxy
}

type DnsResolverProxyBase struct {
	resolver DnsResolverProxy
}

func (s *DnsResolverProxyBase) initDnsResolverBase(resolver DnsResolverProxy) {
	s.resolver = resolver
}

func (s *DnsResolverProxyBase) AsAsync() AsyncDnsResolver {
	return NewAsyncDnsResolverImpl(s.resolver)
}

func (s *DnsResolverProxyBase) AsResolver() DnsResolver {
	return NewDnsResolverImpl(s.resolver)
}

func (s *DnsResolverProxyBase) WithCache() DnsResolverProxy {
	return NewDnsCache(s.resolver)
}

func (s *DnsResolverProxyBase) WithDnssec() DnsResolverProxy {
	return NewDnssecResolver(s.resolver, NewDnssecValidator(s.resolver))
}

func (s *DnsResolverProxyBase) WithBadger() DnsResolverProxy {
	return NewBadgerService(s.resolver)
}

func (s *DnsResolverProxyBase) WithLog() DnsResolverProxy {
	return NewDnsLog(s.resolver)
}

func (s *DnsResolverProxyBase) WithRateLimiting() DnsResolverProxy {
	return NewDnsRateLimiting(s.resolver)
}
