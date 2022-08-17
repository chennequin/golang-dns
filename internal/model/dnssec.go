package model

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

// VerifySig verifies signature of the given RRSET, RRSIG against the specified DNSKEY set
func (r DnsMsg) VerifySig(ksk *dns.DNSKEY) error {

	rrset := r.GetRR()
	rrsig := r.GetRRSIG()

	if len(rrset) == 0 {
		return fmt.Errorf("must provide rrset")
	}

	if rrsig == nil {
		return fmt.Errorf("must provide rrsig")
	}

	if ksk == nil {
		return fmt.Errorf("must provide ksk")
	}

	// verify rrset signature against the key
	err := rrsig.Verify(ksk, rrset)
	if err != nil {
		return fmt.Errorf("invalid RRSIG: %s", err.Error())
	}

	if !rrsig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("invalid RRSIG period")
	}

	return nil
}
