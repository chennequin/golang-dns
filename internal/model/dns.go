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

func (r DnsMsg) GetRrsigDN() string {
	target := r.m.Question[0].Name
	for _, v := range r.m.Answer {
		if t, ok := v.(*dns.RRSIG); ok {
			target = t.Hdr.Name
			break
		}
		target = v.Header().Name
	}
	return target
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

func (r DnsMsg) GetDNSKEY() []*dns.DNSKEY {
	dnsKeys := make([]*dns.DNSKEY, 0, 10)
	for _, v := range r.m.Answer {
		if v.Header().Rrtype == dns.TypeDNSKEY {
			dnsKeys = append(dnsKeys, v.(*dns.DNSKEY))
		}
	}
	return dnsKeys
}

func (r DnsMsg) ByKeyTag(keyTag uint16) *dns.DNSKEY {
	for _, v := range r.m.Answer {
		if t, ok := v.(*dns.DNSKEY); ok {
			if t.KeyTag() == keyTag {
				return t
			}
		}
	}
	return nil
}

func (r DnsMsg) GetRRSIG() []*dns.RRSIG {
	rrsig := make([]*dns.RRSIG, 0, 10)
	for _, v := range r.m.Answer {
		if v.Header().Rrtype == dns.TypeRRSIG {
			rrsig = append(rrsig, v.(*dns.RRSIG))
		}
	}
	return rrsig
}

func (r DnsMsg) GetDS() *dns.DS {
	if rr := h.CollectOne(r.m.Answer, dns.TypeDS); rr != nil {
		return rr.(*dns.DS)
	}
	return nil
}

func (r DnsMsg) GetNSEC3() []*dns.NSEC3 {
	nsec := make([]*dns.NSEC3, 0, 10)
	for _, v := range r.m.Ns {
		if v.Header().Rrtype == dns.TypeNSEC3 {
			nsec = append(nsec, v.(*dns.NSEC3))
		}
	}
	return nsec
}

func (r DnsMsg) IsRRSIG() bool {
	return len(r.GetRRSIG()) > 0
}

func (r DnsMsg) IsEmpty() bool {
	return r.m.Answer == nil
}

func (r DnsMsg) String() string {
	return fmt.Sprintf("AsyncDnsMsg: %s", r.m)
}
