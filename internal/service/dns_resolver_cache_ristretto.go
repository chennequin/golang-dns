package service

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsCache struct {
	DnsResolverBase
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

	var rsv DnsCache

	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000, // number of keys to track frequency of.
		MaxCost:     1000, // maximum cost of cache.
		BufferItems: 64,   // number of keys per Get buffer.
	})
	if err != nil {
		transverse.Logger().Fatal(err)
	}

	rsv.resolver = resolver
	rsv.cache = cache

	return rsv
}

func (rsv DnsCache) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	key := NewDnsCacheKey(name, dnsType)
	value, found := rsv.cache.Get(key)
	if !found {
		r, err := rsv.resolver.Query(name, dnsType)
		if err == nil {
			rsv.cache.SetWithTTL(key, NewDnsCacheEntry(r), 1, r.GetTTL())
			rsv.cache.Wait()
		}
		return r, err
	}

	return value.(DnsCacheEntry).response, nil
}

func (_ DnsCache) String() string {
	return fmt.Sprintf("DnsCache")
}
