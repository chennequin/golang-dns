package main

import (
	"golang-dns/internal/server"
	"log"
)

func main() {
	err := server.RunLocalUDPServer("udp4", ":53")
	if err != nil {
		log.Fatalf("unable to run server: %v", err)
	}
}
