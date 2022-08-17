package model

import (
	"fmt"
	"github.com/miekg/dns"
)

type DnsKeyMsg struct {
	DnsMsg
}

func NewDnsKeyResponse(m *dns.Msg) DnsKeyMsg {
	return DnsKeyMsg{DnsMsg: DnsMsg{m: m}}
}

func (r DnsKeyMsg) KSK() *dns.DNSKEY {
	return r.ByKeyTag(r.GetRRSIG().KeyTag)
}

func (r DnsKeyMsg) ByKeyTag(keyTag uint16) *dns.DNSKEY {
	for _, v := range r.m.Answer {
		if t, ok := v.(*dns.DNSKEY); ok {
			if t.KeyTag() == keyTag {
				return t
			}
		}
	}
	return nil
}

func (r DnsKeyMsg) VerifyRRSIG() error {
	return r.VerifySig(r.KSK())
}

// VerifyTrustAnchor compares the KSK with the specified trust anchor
func (r DnsKeyMsg) VerifyTrustAnchor(anchors []IanaKeyDigest) error {

	kk := r.KSK()

	for _, k := range anchors {
		if err := CompareDsDigest(kk, k.DigestType, k.Digest); err == nil {
			return nil
		}
	}

	return fmt.Errorf("keys are different")
}
