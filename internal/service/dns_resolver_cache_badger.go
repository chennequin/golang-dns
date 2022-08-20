package service

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
	"log"
	"time"
)

const (
	path       = "/tmp/badger"
	defaultTTL = 24 * time.Hour
)

type BadgerService struct {
	DnsResolverBase
	resolver DnsResolver
	db       *badger.DB
	w        chan model.DnsMsg
	r        chan model.DnsCacheKey
}

func NewBadgerService(resolver DnsResolver) DnsResolver {
	var b BadgerService
	defer transverse.Logger().Printf("%s initialized", &b)
	defer b.initDnsResolverBase(&b)

	b.resolver = resolver
	b.w = make(chan model.DnsMsg, nonBlockingChannel)
	b.r = make(chan model.DnsCacheKey, nonBlockingChannel)

	db, err := badger.Open(badger.DefaultOptions(path))
	if err != nil {
		log.Fatal(err)
	}

	b.db = db

	b.ContinuouslyRead()
	b.ContinuouslyStore()

	// preload in cache the dns queries that are stored in database.
	// next resolver must be a cache resolver.
	err = b.IteratePushOverKeys()
	if err != nil {
		log.Fatal(err)
	}

	return &b
}

func (b BadgerService) Query(name string, dnsType uint16) (model.DnsMsg, error) {
	rm := model.NewDnsMsg(h.Msg(name, dnsType))
	return b.Proxy(rm)
}

func (b BadgerService) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {

	proxy, err := b.resolver.Proxy(rm)
	if err != nil {
		return proxy, err
	}

	b.w <- proxy // store result in the background

	return proxy, err
}

func (b BadgerService) ContinuouslyStore() {
	go func() {
		for {
			rm := <-b.w
			if err := b.StoreEntry(b.db, rm); err != nil {
				transverse.LoggerError().Printf("unable to store data: %s", err.Error())
			}
		}
	}()
}

func (b BadgerService) ContinuouslyRead() {
	go func() {
		for {
			k := <-b.r
			_, err := b.resolver.Query(k.Decode())
			if err != nil {
				transverse.LoggerError().Printf("unable to query resolver: %s", err.Error())
				continue
			}
		}
	}()
}

func (b BadgerService) IteratePushOverKeys() error {

	transverse.Logger().Println("Iterating over keys")

	err := b.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			b.r <- model.DnsCacheKey(it.Item().Key())
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error iterating over keys %s", err.Error())
	}

	return nil
}

func (b BadgerService) StoreEntry(db *badger.DB, rm model.DnsMsg) error {

	key := model.NewDnsCacheKey(rm.GetDN(), rm.GetDnsType())

	err := db.Update(func(txn *badger.Txn) error {
		entry, err := model.NewDnsBadgerEntry(rm.GetMsg()).AsBytes()
		if err != nil {
			return fmt.Errorf("error marshalling msg %s", err.Error())
		}
		e := badger.NewEntry([]byte(key), entry).WithTTL(defaultTTL)
		return txn.SetEntry(e)
	})

	return err
}

func (b BadgerService) Close() {
	_ = b.db.Close()
}

func (b BadgerService) String() string {
	return fmt.Sprintf("BadgerService %s", path)
}
