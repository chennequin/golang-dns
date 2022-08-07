package service

import (
	"fmt"
	"github.com/miekg/dns"
	"golang-dns/internal/helpers"
	"golang-dns/internal/transverse"
)

type DnsResolver interface {
	Query(name string, dnsType uint16) ([]dns.RR, *dns.RRSIG, error)
}

type DnsResolverRestyImpl struct {
	client HardenedResty
	url    string
}

func NewDnsResolverRestyImpl(client HardenedResty, url string) DnsResolver {
	var r DnsResolverRestyImpl
	defer transverse.Logger().Printf("%s initialized", &r)
	r.client = client
	r.url = url
	return r
}

func (s DnsResolverRestyImpl) Query(name string, dnsType uint16) ([]dns.RR, *dns.RRSIG, error) {
	if _, valid := dns.IsDomainName(name); !valid {
		return nil, nil, fmt.Errorf("must provide a valid domain name")
	}
	m := helpers.Msg(name, dnsType)
	rr, rrSig, err := s.QueryRrSig(m, dnsType)
	return rr, rrSig, err
}

func (s DnsResolverRestyImpl) QueryRrSig(m *dns.Msg, dnsType uint16) ([]dns.RR, *dns.RRSIG, error) {

	in, err := s.exchange(m)
	if err != nil {
		return nil, nil, err
	}

	rr := helpers.CollectAll(in.Answer, dnsType)
	rrsig := helpers.CollectOne(in.Answer, dns.TypeRRSIG)

	if rrsig != nil {
		return rr, rrsig.(*dns.RRSIG), nil
	}

	return rr, nil, nil
}

func (s DnsResolverRestyImpl) exchange(m *dns.Msg) (*dns.Msg, error) {

	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("unable to pack dns.Msg")
	}

	resp, err := s.client.Client().R().
		SetHeader("Content-Type", "application/dns-message").
		SetBody(b).
		Post(s.url)
	if err != nil {
		return nil, fmt.Errorf("unable to perform query: %s", err.Error())
	}

	if transverse.EnableTrace {
		helpers.LogTrace(resp, err)
	}

	in := new(dns.Msg)
	err = in.Unpack(resp.Body())
	if err != nil {
		return nil, fmt.Errorf("unable to unpack dns.Msg")
	}

	if !in.MsgHdr.RecursionAvailable ||
		in.MsgHdr.CheckingDisabled {
		return in, fmt.Errorf("not acceptable response received %+v", in.MsgHdr)
	}

	return in, nil
}

func (s DnsResolverRestyImpl) String() string {
	return fmt.Sprintf("DnsResolverRestyImpl %s", s.url)
}
