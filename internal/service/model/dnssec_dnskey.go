package model

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
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
	ksk := r.KSK()
	if err := r.VerifySig(ksk); err != nil {
		return fmt.Errorf("invalid signature: %s", err.Error())
	}
	return nil
}

// VerifyTrustAnchor compares the KSK with the specified trust anchor
func (r DnsKeyResponse) VerifyTrustAnchor(anchors []IanaKeyDigest) error {

	kk := r.KSK()

	for _, k := range anchors {

		digest := strings.ToUpper(kk.ToDS(k.DigestType).Digest)

		if kk.KeyTag() == k.KeyTag &&
			kk.Algorithm == k.Algorithm &&
			digest == k.Digest {
			return nil
		}
	}

	return fmt.Errorf("keys are different")
}
