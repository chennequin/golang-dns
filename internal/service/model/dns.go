package model

import (
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"time"
)

const (
	defaultTTL = 5 * time.Minute
)

type DnsResponse struct {
	m *dns.Msg
}

func NewDnsResponse(m *dns.Msg) DnsResponse {
	return DnsResponse{m: m}
}

func (r DnsResponse) GetTTL() time.Duration {
	if len(r.m.Answer) > 0 {
		return time.Duration(r.m.Answer[0].Header().Ttl) * time.Second
	}
	return defaultTTL
}

func (r DnsResponse) GetDN() string {
	return r.m.Question[0].Name
}

func (r DnsResponse) GetDnsType() uint16 {
	return r.m.Question[0].Qtype
}

func (r DnsResponse) GetMsg() *dns.Msg {
	return r.m
}

func (r DnsResponse) GetRR() []dns.RR {
	return h.CollectAll(r.m.Answer, r.GetDnsType())
}

func (r DnsResponse) GetFRR(dnsType uint16) []dns.RR {
	return h.CollectAll(r.m.Answer, dnsType)
}

func (r DnsResponse) GetDNSKEY() []dns.RR {
	return h.CollectAll(r.m.Answer, dns.TypeDNSKEY)
}

func (r DnsResponse) GetRRSIG() *dns.RRSIG {
	if rrsig := h.CollectOne(r.m.Answer, dns.TypeRRSIG); rrsig != nil {
		return rrsig.(*dns.RRSIG)
	}
	return nil
}

func (r DnsResponse) GetDS() *dns.DS {
	if rr := h.CollectOne(r.m.Answer, dns.TypeDS); rr != nil {
		return rr.(*dns.DS)
	}
	return nil
}

func (r DnsResponse) IsRRSIG() bool {
	return r.GetRRSIG() != nil
}
