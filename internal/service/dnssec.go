package service

import (
	"fmt"
	"github.com/miekg/dns"
	"golang-dns/internal/helpers"
	"golang-dns/internal/transverse"
	"time"
)

type DnssecValidator struct {
	resolver    DnsResolver
	trustAnchor dns.DNSKEY
}

func NewDnssecValidator(resolver DnsResolver, trustAnchor dns.DNSKEY) DnssecValidator {
	var v DnssecValidator
	defer transverse.Logger().Printf("%s initialized", &v)
	v.resolver = resolver
	v.trustAnchor = trustAnchor
	return v
}

func (s DnssecValidator) VerifySig(rrset []dns.RR, rrsig *dns.RRSIG) error {
	domain := rrset[0].Header().Name
	return s.VerifySigRec(domain, rrset, rrsig)
}

func (s DnssecValidator) VerifySigRec(zone string, rrset []dns.RR, rrsig *dns.RRSIG) error {

	if rrsig == nil {
		return fmt.Errorf("zone: %s - no signature", zone)
	}

	if !dns.IsRRset(rrset) {
		return fmt.Errorf("zone: %s - invalid rrset provided", zone)
	}

	// obtaining the ZSK and KSK for the zone
	kkArr, kksig, err := s.resolver.Query(zone, dns.TypeDNSKEY)
	kkMap := helpers.AsDnsKeyMap(kkArr)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to obtain DNSKEY: %s", zone, err.Error())
	}

	//TODO validate dnssec from TOP to BOTTOM
	// -> this way I would not have to query DNSKEY for _dmarc.icourrier.fr
	if len(kkArr) < 1 {
		// DNSKEY not found -> query the parent zone
		return s.VerifySigRec(helpers.ParentZone(zone), rrset, rrsig)
	}

	// verify RR signature

	err = rrsig.Verify(kkMap[rrsig.KeyTag], rrset)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to verify RR RRSIG: %s", zone, err.Error())
	}

	if !rrsig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("zone: %s - invalid validity period for RR RRSIG", zone)
	}

	if transverse.LogDnssec {
		transverse.Logger().Printf("zone %s - %T signature: valid", zone, rrset[0])
	}

	// verify DNSKEY signature
	err = kksig.Verify(kkMap[kksig.KeyTag], kkArr)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to verify DNSKEY RRSIG: %s", zone, err.Error())
	}

	if !kksig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("zone: %s - invalid validity period for DNSKEY RRSIG", zone)
	}

	if transverse.LogDnssec {
		transverse.Logger().Printf("zone %s - %T signature: valid", zone, &dns.DNSKEY{})
	}

	if zone == "." {
		// this is the end of recursion

		// find the KSK of root zone .
		kk := kkMap[kksig.KeyTag]

		// and compare it with the trust anchor
		if kk.KeyTag() != s.trustAnchor.KeyTag() ||
			kk.Flags != s.trustAnchor.Flags ||
			kk.Algorithm != s.trustAnchor.Algorithm ||
			kk.Protocol != s.trustAnchor.Protocol {
			return fmt.Errorf("unable to validate trust chain up to the trust anchor")
		}

		if transverse.LogDnssec {
			transverse.Logger().Printf("zone %s - trust anchor matches %T", zone, kk)
		}
		return nil
	}

	// obtaining DS for the zone

	dsArr, dssig, err := s.resolver.Query(zone, dns.TypeDS)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to obtain DS: %s", zone, err.Error())
	}
	if len(dsArr) < 1 {
		return fmt.Errorf("zone: %s - unable to obtain DS", zone)
	}

	// verify DS hash

	ds := dsArr[0].(*dns.DS)

	calcDS := kkMap[kksig.KeyTag].ToDS(ds.DigestType)
	if ds.Digest != calcDS.Digest || kksig.KeyTag != ds.KeyTag {
		return fmt.Errorf("zone: %s - invalid DS digest", zone)
	}

	if transverse.LogDnssec {
		transverse.Logger().Printf("zone %s - %T digest: valid", zone, ds)
	}

	return s.VerifySigRec(helpers.ParentZone(zone), []dns.RR{ds}, dssig)
}

func (s DnssecValidator) VerifySigRecTopDown(zone string, rrset []dns.RR, rrsig *dns.RRSIG) error {

	return nil
}

func (_ DnssecValidator) String() string {
	return fmt.Sprintf("DnssecValidator")
}
