package main

import (
	"golang-dns/internal/server"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	s, err := server.RunLocalUDPServer("udp4", ":53")
	if err != nil {
		log.Fatalf("unable to run server: %v", err)
	}
	defer func() { _ = s.Shutdown() }()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	ss := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", ss)

}
