package server

import (
	"github.com/miekg/dns"
	"golang-dns/internal/model"
	"golang-dns/internal/providers"
	"golang-dns/internal/service"
	t "golang-dns/internal/transverse"
)

type DnsOverHttpsHandler struct {
	resolver service.DnsResolverProxy
}

func NewDnsOverHttpsHandler() DnsOverHttpsHandler {
	return DnsOverHttpsHandler{
		resolver: providers.NewGoogleDnsPool().WithLog().WithCache().WithDnssec().WithBadger().WithRateLimiting(),
	}
}

// ServeDNS implements the dns.Handler interface
func (h DnsOverHttpsHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {

	rm, err := h.resolver.Proxy(model.NewDnsMsg(req))

	if err != nil {
		t.LoggerError().Printf("error in resolver: %s", err.Error())
	}

	if err = w.WriteMsg(rm.GetMsg()); err != nil {
		t.LoggerError().Printf("error in WriteMsg: %s", err.Error())
	}
}
