package server

import (
	"github.com/miekg/dns"
	"golang-dns/internal/model"
	"golang-dns/internal/service"
	t "golang-dns/internal/transverse"
)

type DnsOverHttpsHandler struct {
	resolver service.DnsResolverProxy
}

func NewDnsOverHttpsHandler(resolver service.DnsResolverProxy) DnsOverHttpsHandler {
	return DnsOverHttpsHandler{
		resolver: resolver,
	}
}

// ServeDNS implements the dns.Handler interface
func (h DnsOverHttpsHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {

	rm, err := h.resolver.Proxy(model.NewDnsMsg(req))

	if err != nil {
		t.LoggerError().Printf("error in resolver: %s", err.Error())
		h.WriteMsg(w, req)
		return
	}

	h.WriteMsg(w, rm.GetMsg())
}

func (h DnsOverHttpsHandler) WriteMsg(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		t.LoggerError().Printf("error in WriteMsg: %s", err.Error())
	}
}
