package service

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"golang-dns/internal/transverse"
	"time"
)

type DnsCache struct {
	resolver DnsResolver
	cache    *ristretto.Cache
}

type DnsCacheEntry struct {
	rr    []dns.RR
	rrsig *dns.RRSIG
}

func (e DnsCacheEntry) String() string {
	return fmt.Sprintf("{rr:%s, rrsig:%s}", e.rr, e.rrsig)
}

type DnsCacheKey string

func NewDnsCacheKey(name string, dnsType uint16) string {
	return fmt.Sprintf("%s/%d", name, dnsType)
}

func NewDnsEntry(rr []dns.RR, rrsig *dns.RRSIG) DnsCacheEntry {
	return DnsCacheEntry{
		rr:    rr,
		rrsig: rrsig,
	}
}

func NewDnsCache(resolver DnsResolver) DnsCache {

	var c DnsCache

	defer transverse.Logger().Printf("%s initialized", &c)

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000, // number of keys to track frequency of.
		MaxCost:     1000, // maximum cost of cache.
		BufferItems: 64,   // number of keys per Get buffer.
	})
	if err != nil {
		transverse.Logger().Fatal(err)
	}

	c.resolver = resolver
	c.cache = cache

	return c
}

func (s DnsCache) Query(name string, dnsType uint16) ([]dns.RR, *dns.RRSIG, error) {

	rrTTL := func(rr []dns.RR) time.Duration {
		if len(rr) > 0 {
			return time.Duration(rr[0].Header().Ttl) * time.Second
		}
		return 5 * time.Minute
	}

	key := NewDnsCacheKey(name, dnsType)
	value, found := s.cache.Get(key)
	if !found {
		rr, rrsig, err := s.resolver.Query(name, dnsType)
		if err == nil {
			s.cache.SetWithTTL(key, NewDnsEntry(rr, rrsig), 1, rrTTL(rr))
			s.cache.Wait()
		}
		return rr, rrsig, err
	}

	rr := value.(DnsCacheEntry).rr
	rrsig := value.(DnsCacheEntry).rrsig

	return rr, rrsig, nil
}

func (_ DnsCache) String() string {
	return fmt.Sprintf("DnsCache")
}
