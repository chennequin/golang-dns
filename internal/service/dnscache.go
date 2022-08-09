package service

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	"golang-dns/internal/service/model"
	"golang-dns/internal/transverse"
)

type DnsCache struct {
	resolver DnsResolver
	cache    *ristretto.Cache
}

type DnsCacheEntry struct {
	name     string
	dnsType  uint16
	response model.DnsResponse
}

func (e DnsCacheEntry) String() string {
	return fmt.Sprintf("{m:%v}", e.response.GetMsg())
}

type DnsCacheKey string

func NewDnsCacheKey(name string, dnsType uint16) string {
	return fmt.Sprintf("%s/%d", name, dnsType)
}

func NewDnsCacheEntry(r model.DnsResponse) DnsCacheEntry {
	return DnsCacheEntry{
		response: r,
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

func (s DnsCache) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	key := NewDnsCacheKey(name, dnsType)
	value, found := s.cache.Get(key)
	if !found {
		r, err := s.resolver.Query(name, dnsType)
		if err == nil {
			s.cache.SetWithTTL(key, NewDnsCacheEntry(r), 1, r.GetTTL())
			s.cache.Wait()
		}
		return r, err
	}

	return value.(DnsCacheEntry).response, nil
}

func (_ DnsCache) String() string {
	return fmt.Sprintf("DnsCache")
}
