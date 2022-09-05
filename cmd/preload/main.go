package main

import (
	"golang-dns/internal/providers"
	"golang-dns/internal/service"
)

func main() {

	resolver := providers.NewGoogleDnsPool().WithLog().WithCache().WithDnssec()
	badger := service.NewBadger()

	p := service.NewDnsCachePreload(resolver, badger)
	p.Preload()
}
