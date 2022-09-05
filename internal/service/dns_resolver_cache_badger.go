package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

const (
	workers = 10
)

type DnsCacheBadger struct {
	DnsResolverProxyBase
	resolver DnsResolverProxy
	db       Badger
	w        chan model.DnsMsg
}

func NewDnsCacheBadger(resolver DnsResolverProxy, db Badger) DnsResolverProxy {
	var b DnsCacheBadger
	defer transverse.Logger().Printf("%s initialized", &b)
	defer b.initDnsResolverBase(&b)

	b.resolver = resolver
	b.db = db
	b.w = make(chan model.DnsMsg, nonBlockingChannel)

	b.ContinuouslyStore()

	return &b
}

func (b DnsCacheBadger) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	proxy, err := b.resolver.Proxy(rm)
	if err != nil {
		return proxy, err
	}

	b.w <- proxy // store result in the background

	return proxy, err
}

func (b DnsCacheBadger) ContinuouslyStore() {
	go func() {
		for {

			rm := <-b.w

			key := []byte(model.NewDnsCacheKey(rm))
			entry, err := model.NewDnsBadgerEntry(rm)
			if err != nil {
				transverse.LoggerError().Println(fmt.Errorf("error packing badger msg %s", err.Error()))
				continue
			}

			err = b.db.StoreEntry(key, entry.AsBytes())
			if err != nil {
				transverse.LoggerError().Println(fmt.Errorf("unable to store data: %s", err.Error()))
				continue
			}
		}
	}()
}

func (b DnsCacheBadger) String() string {
	return fmt.Sprintf("DnsCacheBadger %s", path)
}
