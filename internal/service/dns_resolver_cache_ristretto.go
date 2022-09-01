package service

import (
	"fmt"
	"github.com/dgraph-io/ristretto"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsCache struct {
	DnsResolverProxyBase
	resolver DnsResolverProxy
	cache    *ristretto.Cache
}

func NewDnsCache(resolver DnsResolverProxy) DnsResolverProxy {

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

func (rsv DnsCache) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	key := model.NewDnsCacheKey(rm)
	value, found := rsv.cache.Get(key)
	if !found {
		nrm, err := rsv.resolver.Proxy(rm)
		if err == nil {
			entry, err := model.NewDnsRistrettoEntry(nrm)
			if err != nil {
				transverse.LoggerError().Printf("unable to pack ristretto entry: %s", err.Error())
				return nrm, nil
			}
			rsv.cache.SetWithTTL(key, entry, 1, nrm.GetTTL())
			rsv.cache.Wait()
		}
		return nrm, err
	}

	// adapt to the id of the request avoiding errors like
	// ;; Warning: ID mismatch: expected ID 34825, got 13184
	nrm, err := value.(model.DnsRistrettoEntry).Value()
	if err != nil {
		return nrm, fmt.Errorf("found corrupted ristretto entry: %s", err.Error())
	}
	nrm.GetMsg().Id = rm.GetMsg().Id

	return nrm, nil

}

func (_ DnsCache) String() string {
	return fmt.Sprintf("DnsCache")
}
