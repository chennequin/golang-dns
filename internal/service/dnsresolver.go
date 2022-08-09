package service

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/service/model"
	"golang-dns/internal/transverse"
)

type DnsResolver interface {
	Query(name string, dnsType uint16) (model.DnsResponse, error)
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

func (s DnsResolverRestyImpl) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	m := h.Msg(name, dnsType)
	r := model.NewDnsResponse(m)

	if _, valid := dns.IsDomainName(name); !valid {
		return r, fmt.Errorf("must provide a valid domain name")
	}

	in, err := s.packPostUnpack(m)
	return model.NewDnsResponse(in), err
}

func (s DnsResolverRestyImpl) packPostUnpack(m *dns.Msg) (*dns.Msg, error) {

	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("unable to pack dns.Msg")
	}

	resp, err := s.Post(b)
	if err != nil {
		return nil, fmt.Errorf("unable to perform query: %s", err.Error())
	}

	if transverse.FlagHttpEnableTrace {
		h.LogTrace(resp, err)
	}

	in := new(dns.Msg)
	err = in.Unpack(resp.Body())
	if err != nil {
		return in, fmt.Errorf("unable to unpack dns.Msg")
	}

	// this client does not handler recursive queries.
	// reject the answer if recursion is not available on the server side.
	if !in.MsgHdr.RecursionAvailable ||
		in.MsgHdr.CheckingDisabled {
		return in, fmt.Errorf("not acceptable response received %+v", in.MsgHdr)
	}

	return in, nil
}

func (s DnsResolverRestyImpl) Post(b []byte) (*resty.Response, error) {
	return s.client.Client().R().
		SetHeader("Content-Type", "application/dns-message").
		SetBody(b).
		Post(s.url)
}

func (s DnsResolverRestyImpl) String() string {
	return fmt.Sprintf("DnsResolverRestyImpl %s", s.url)
}
