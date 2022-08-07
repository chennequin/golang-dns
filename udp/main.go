package main

import (
	"context"
	"net"
	"time"
)

func main() {
	r := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "udp", "9.9.9.9:53")
		},
	}
	ip, _ := r.LookupHost(context.Background(), "icourrier.fr")

	println(ip[0])
}
