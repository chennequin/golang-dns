package service

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	h "golang-dns/internal/helpers"
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
	response model.DnsMsg
}

func (e DnsCacheEntry) String() string {
	return fmt.Sprintf("{m:%v}", e.response.GetMsg())
}

type DnsCacheKey string

func NewDnsCacheKey(name string, dnsType uint16) string {
	return fmt.Sprintf("%s/%d", name, dnsType)
}

func NewDnsCacheEntry(r model.DnsMsg) DnsCacheEntry {
	return DnsCacheEntry{
		response: r,
	}
}

func NewDnsCache(resolver DnsResolver) DnsResolver {

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

	return &rsv
}

func (rsv DnsCache) Query(name string, dnsType uint16) (model.DnsMsg, error) {
	rm := model.NewDnsMsg(h.Msg(name, dnsType))
	return rsv.Proxy(rm)
}

func (rsv DnsCache) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	key := NewDnsCacheKey(rm.GetDN(), rm.GetDnsType())
	value, found := rsv.cache.Get(key)
	if !found {
		nrm, err := rsv.resolver.Proxy(rm)
		if err == nil {
			rsv.cache.SetWithTTL(key, NewDnsCacheEntry(nrm), 1, nrm.GetTTL())
			rsv.cache.Wait()
		}
		return nrm, err
	}

	// adapt to the id of the request avoiding errors like
	// ;; Warning: ID mismatch: expected ID 34825, got 13184
	nrm := value.(DnsCacheEntry).response
	nrm.GetMsg().Id = rm.GetMsg().Id

	return nrm, nil

}

func (_ DnsCache) String() string {
	return fmt.Sprintf("DnsCache")
}
