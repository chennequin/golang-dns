package server

import (
	"github.com/miekg/dns"
	t "golang-dns/internal/transverse"
	"net"
	"sync"
)

func RunLocalUDPServer(network, addr string) (*dns.Server, error) {

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()

	server := &dns.Server{
		PacketConn: pc,
		Handler:    NewDnsOverHttpsHandler(),
		NotifyStartedFunc: func() {
			waitLock.Unlock()
			t.Logger().Printf("server started %s%s", network, addr)
		},
	}

	var fin chan error
	go func() {
		fin <- server.ActivateAndServe()
		if err = pc.Close(); err != nil {
			t.LoggerError().Printf("error closing PacketConn: %s", err.Error())
		}
	}()

	waitLock.Lock()

	return server, err
}
