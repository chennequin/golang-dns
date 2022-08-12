package service

type DnsResolverBase struct {
	resolver DnsResolver
}

func (s DnsResolverBase) initDnsResolverBase(resolver DnsResolver) {
	s.resolver = resolver
}

func (s DnsResolverBase) AsAsync() AsyncDnsResolver {
	return NewAsyncDnsResolverImpl(s.resolver)
}
