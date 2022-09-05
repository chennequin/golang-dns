package main

import (
	"golang-dns/internal/providers"
	"golang-dns/internal/server"
	"golang-dns/internal/service"
	"log"
)

func main() {

	resolver := providers.NewGoogleDnsPool().WithLog().WithCache().WithDnssec().WithBadger(service.NewBadger()).WithRateLimiting()

	//go func() { server.StartGin(resolver) }()

	err := server.RunLocalUDPServer("udp4", ":53", resolver)
	if err != nil {
		log.Fatalf("unable to run server: %v", err)
	}
}
