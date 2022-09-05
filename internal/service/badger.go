package service

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"golang-dns/internal/transverse"
	"log"
	"time"
)

const (
	path       = "/tmp/badger"
	defaultTTL = 24 * time.Hour
)

type Badger struct {
	db *badger.DB
}

func NewBadger() Badger {
	var b Badger
	defer transverse.Logger().Printf("%s initialized", &b)

	db, err := badger.Open(badger.DefaultOptions(path))
	if err != nil {
		log.Fatal(err)
	}

	b.db = db

	return b
}

func (b Badger) StoreEntry(key, data []byte) error {

	err := b.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, data).WithTTL(defaultTTL)
		return txn.SetEntry(e)
	})

	return err
}

func (b Badger) IterateOverKeys(fn func([]byte)) error {

	transverse.Logger().Println("Iterating over keys")

	err := b.db.View(func(txn *badger.Txn) error {

		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		// iterate over all keys
		for it.Rewind(); it.Valid(); it.Next() {
			fn(it.Item().Key())
		}

		return nil
	})

	return err
}

func (b Badger) Close() {
	_ = b.db.Close()
}

func (b Badger) String() string {
	return fmt.Sprintf("DnsCacheBadger %s", path)
}
