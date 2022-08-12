package model

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

type DsResponse struct {
	DnsResponse
}

func NewDnsDsResponse(m *dns.Msg) DsResponse {
	return DsResponse{DnsResponse: DnsResponse{m: m}}
}

// VerifyRRSIG verifies DS signature given the specified key
func (r DsResponse) VerifyRRSIG(keyResponse *DnsKeyResponse) error {

	rrk := keyResponse.ByKeyTag(r.GetRRSIG().KeyTag) // key which signed DS in parent zone
	return r.VerifySig(rrk)
}

// CompareDsDigest calculates the DS digest of the specified key and compares with the specified digest
func CompareDsDigest(kk *dns.DNSKEY, digestType uint8, digest string) error {

	// calculate DS hash using zone KSK
	calc := strings.ToUpper(kk.ToDS(digestType).Digest)
	expected := strings.ToUpper(digest)
	if calc != expected {
		return fmt.Errorf("invalid digest hash")
	}
	return nil
}
