package model

import (
	"fmt"
	"github.com/miekg/dns"
)

type DnsKeyResponse struct {
	DnsResponse
}

func NewDnsKeyResponse(m *dns.Msg) DnsKeyResponse {
	return DnsKeyResponse{DnsResponse: DnsResponse{m: m}}
}

func (r DnsKeyResponse) KSK() *dns.DNSKEY {
	return r.ByKeyTag(r.GetRRSIG().KeyTag)
}

func (r DnsKeyResponse) ByKeyTag(keyTag uint16) *dns.DNSKEY {
	for _, v := range r.m.Answer {
		if t, ok := v.(*dns.DNSKEY); ok {
			if t.KeyTag() == keyTag {
				return t
			}
		}
	}
	return nil
}

func (r DnsKeyResponse) VerifyRRSIG() error {
	return r.VerifySig(r.KSK())
}

// VerifyTrustAnchor compares the KSK with the specified trust anchor
func (r DnsKeyResponse) VerifyTrustAnchor(anchors []IanaKeyDigest) error {

	kk := r.KSK()

	for _, k := range anchors {
		if err := CompareDsDigest(kk, k.DigestType, k.Digest); err == nil {
			return nil
		}
	}

	return fmt.Errorf("keys are different")
}
