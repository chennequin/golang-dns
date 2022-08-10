package model

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

// VerifySig verifies signature of the given RRSET, RRSIG against the specified DNSKEY set
func (r DnsResponse) VerifySig(ksk *dns.DNSKEY) error {

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

// FindVerifySig verifies that the given RRSET, RRSIG has a valid signature against the specified key set.
// returns true if a signing key has been found, false otherwise.
func (r DnsResponse) FindVerifySig(k *DnsKeyResponse) (bool, error) {

	rrsig := r.GetRRSIG()
	sk := k.ByKeyTag(rrsig.KeyTag)

	if sk != nil {

		if err := r.VerifySig(sk); err != nil {
			return true, fmt.Errorf("invalid RR/RRSIG: %s", err.Error())
		}
		return true, nil
	}

	return false, nil
}
