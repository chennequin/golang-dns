package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
	"log"
)

type DnsCachePreload struct {
	resolver DnsResolverProxy
	db       Badger
	r        chan model.DnsCacheKey
}

func NewDnsCachePreload(resolver DnsResolverProxy, db Badger) DnsCachePreload {
	var b DnsCachePreload
	defer transverse.Logger().Printf("%s initialized", &b)

	b.resolver = resolver
	b.db = db
	b.r = make(chan model.DnsCacheKey, nonBlockingChannel)

	return b
}

func (b DnsCachePreload) Preload() {

	// close channel hence terminating the ContinuouslyRead() function
	defer close(b.r)

	b.ContinuouslyRead()

	// preload in cache the dns queries that are stored in database.
	err := b.db.IterateOverKeys(func(key []byte) {
		b.r <- model.DnsCacheKey(key)
	})

	if err != nil {
		log.Fatal(err)
	}
}

func (b DnsCachePreload) ContinuouslyRead() {
	for i := 0; i < workers; i++ {
		go func() {
			for k := range b.r {
				_, err := b.resolver.Proxy(k.ToDnsMsg())
				if err != nil {
					transverse.LoggerError().Printf("unable to query resolver: %s", err.Error())
					continue
				}
			}
		}()
	}
}

func (b DnsCachePreload) String() string {
	return fmt.Sprintf("DnsCachePreload %s", path)
}
