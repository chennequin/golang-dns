package service

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
)

type DnsResolverRestyImpl struct {
	DnsResolverProxyBase
	client HardenedResty
	url    string
}

func NewDnsResolverRestyImpl(client HardenedResty, url string) DnsResolverProxy {
	var rsv DnsResolverRestyImpl
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.client = client
	rsv.url = url
	return &rsv
}

func (rsv DnsResolverRestyImpl) Proxy(rm model.DnsMsg) (model.DnsMsg, error) {
	in, err := rsv.packPostUnpack(rm.WithDNSSEC().GetMsg())
	return model.NewDnsMsg(in), err
}

func (rsv DnsResolverRestyImpl) packPostUnpack(m *dns.Msg) (*dns.Msg, error) {

	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("unable to pack dns.Msg")
	}

	resp, err := rsv.Post(b)
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
		in.MsgHdr.Truncated ||
		in.MsgHdr.CheckingDisabled {
		return in, fmt.Errorf("not acceptable response received %+v", in.MsgHdr)
	}

	return in, nil
}

func (rsv DnsResolverRestyImpl) Post(b []byte) (*resty.Response, error) {
	return rsv.client.Client().R().
		SetHeader("Content-Type", "application/dns-message").
		SetBody(b).
		Post(rsv.url)
}

func (rsv DnsResolverRestyImpl) String() string {
	return fmt.Sprintf("DnsResolverRestyImpl %s", rsv.url)
}
