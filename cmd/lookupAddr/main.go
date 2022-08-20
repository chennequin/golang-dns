package main

import (
	"fmt"
	"golang-dns/internal/server"
	"net"
)

func main() {

	net.DefaultResolver = server.NewUdpLoopBackNetResolver()

	names, err := net.LookupHost("dns.google")
	if err != nil {
		panic(err)
	}

	if len(names) == 0 {
		fmt.Printf("no record")
	}

	for _, name := range names {
		fmt.Printf("****** %s\n", name)
	}
}
