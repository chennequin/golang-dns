package server

import (
	"github.com/miekg/dns"
	"golang-dns/internal/service"
	t "golang-dns/internal/transverse"
	"net"
)

func RunLocalUDPServer(network, addr string, resolver service.DnsResolverProxy) error {

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return err
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    NewDnsOverHttpsHandler(resolver),
		NotifyStartedFunc: func() {
			t.Logger().Printf("server started %s%s", network, addr)
		},
	}

	err = server.ActivateAndServe()
	if err = pc.Close(); err != nil {
		t.LoggerError().Printf("error closing PacketConn: %s", err.Error())
	}

	return err
}
