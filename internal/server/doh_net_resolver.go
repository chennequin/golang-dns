package server

import (
	"context"
	"net"
	"time"
)

func NewLoopBackNetResolver() *net.Resolver {
	dialer := net.Dialer{
		Timeout: time.Second * 2,
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
}
