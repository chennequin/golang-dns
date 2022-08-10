package model

import (
	"fmt"
	"github.com/miekg/dns"
)

type DsResponse struct {
	DnsResponse
}

func NewDnsDsResponse(m *dns.Msg) DsResponse {
	return DsResponse{DnsResponse: DnsResponse{m: m}}
}

// Verify verifies DS integrity for the specified zone given the zone KSK and parent zone ZSK
func (r DsResponse) Verify(keys, parentKeys *DnsKeyResponse) error {

	ksk := keys.KSK()                               // KSK of the zone
	rrk := parentKeys.ByKeyTag(r.GetRRSIG().KeyTag) // key which signed DS in parent zone

	if err := r.VerifySig(rrk); err != nil {
		return fmt.Errorf("invalid DS: %s", err.Error())
	}

	if err := r.VerifyDSHash(ksk); err != nil {
		return fmt.Errorf("invalid DS: %s", err.Error())
	}

	return nil
}

// VerifyDSHash verifies the hash of specified DS against the specified KSK
func (r DsResponse) VerifyDSHash(ksk *dns.DNSKEY) error {

	ds := r.GetDS()

	if ds == nil {
		return fmt.Errorf("must provide DS value")
	}

	if ksk == nil {
		return fmt.Errorf("must provide KSK")
	}

	// calculate DS hash using zone KSK
	calcDS := ksk.ToDS(ds.DigestType)

	// verify DS hash equality
	if ds.Digest != calcDS.Digest || ksk.KeyTag() != ds.KeyTag {
		return fmt.Errorf("invalid digest")
	}

	return nil
}
