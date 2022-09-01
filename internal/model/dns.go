package model

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"time"
)

const (
	defaultTTL = 5 * time.Minute
)

type DnsMsg struct {
	m *dns.Msg
}

func NewDnsMsg(m *dns.Msg) DnsMsg {
	return DnsMsg{m: m}
}

func (r DnsMsg) WithDNSSEC() DnsMsg {

	r.m.RecursionDesired = true // +rev
	r.m.CheckingDisabled = false

	o := r.m.IsEdns0()
	if o == nil {
		r.m.SetEdns0(4096, true) // +dnssec
		return r
	}

	o.SetUDPSize(4096)
	o.SetDo(true)

	return r
}

func (r DnsMsg) GetTTL() time.Duration {
	if len(r.m.Answer) > 0 {
		return time.Duration(r.m.Answer[0].Header().Ttl) * time.Second
	}
	return defaultTTL
}

func (r DnsMsg) GetQuestion() dns.Question {
	return r.m.Question[0]
}

func (r DnsMsg) GetDN() string {
	return r.m.Question[0].Name
}

func (r DnsMsg) GetDnsType() uint16 {
	return r.m.Question[0].Qtype
}

func (r DnsMsg) GetMsg() *dns.Msg {
	return r.m
}

func (r DnsMsg) GetRR() []dns.RR {
	return h.CollectAll(r.m.Answer, r.GetDnsType())
}

func (r DnsMsg) GetDNSKEY() []dns.RR {
	return h.CollectAll(r.m.Answer, dns.TypeDNSKEY)
}

func (r DnsMsg) GetRRSIG() *dns.RRSIG {
	if rrsig := h.CollectOne(r.m.Answer, dns.TypeRRSIG); rrsig != nil {
		return rrsig.(*dns.RRSIG)
	}
	return nil
}

func (r DnsMsg) GetDS() *dns.DS {
	if rr := h.CollectOne(r.m.Answer, dns.TypeDS); rr != nil {
		return rr.(*dns.DS)
	}
	return nil
}

func (r DnsMsg) IsRRSIG() bool {
	return r.GetRRSIG() != nil
}

func (r DnsMsg) IsEmpty() bool {
	return r.m.Answer == nil
}

func (r DnsMsg) AsDsResponse() DsMsg {
	return NewDnsDsResponse(r.m)
}

func (r DnsMsg) AsDnsKeyResponse() DnsKeyMsg {
	return NewDnsKeyResponse(r.m)
}

func (r DnsMsg) String() string {
	return fmt.Sprintf("AsyncDnsMsg: %s", r.m)
}
