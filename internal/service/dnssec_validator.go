package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/service/conf"
	t "golang-dns/internal/transverse"
)

const (
	nonBlockingChannel = 10
)

type DnssecValidator struct {
	resolver      DnsResolver
	asyncResolver AsyncDnsResolver
	anchors       model.IanaAnchors
}

func NewDnssecValidator(resolver DnsResolver) DnssecValidator {
	return NewDnssecValidatorFromIanaFile(resolver, LoadIanaFile(conf.IanaFile))
}

func NewDnssecValidatorFromIanaFile(resolver DnsResolver, anchors model.IanaAnchors) DnssecValidator {
	var v DnssecValidator
	defer t.Logger().Printf("%s initialized", &v)
	v.resolver = resolver
	v.asyncResolver = NewAsyncDnsResolverImpl(resolver)
	v.anchors = anchors
	return v
}

func (s DnssecValidator) Verify(rm model.DnsMsg) error {

	err := s.NewDnssecRecursion().RunVerify(rm)

	if err != nil {
		return fmt.Errorf("signature is invalid: %s", err)
	}

	return nil
}

func (_ DnssecValidator) String() string {
	return fmt.Sprintf("DnssecValidator")
}

/**********************/

type DnssecRecursion struct {
	validator DnssecValidator
	zone      chan DnssecRecursionZone
}

type DnssecRecursionZone struct {
	zone           string
	keyAsyncResult *model.AsyncDnsMsg
	dsAsyncResult  *model.AsyncDnsMsg
}

func (s DnssecValidator) NewDnssecRecursion() DnssecRecursion {
	return DnssecRecursion{
		validator: s,
		zone:      make(chan DnssecRecursionZone, nonBlockingChannel),
	}
}

func (recursion DnssecRecursion) PushToChan(zone string, keyAsyncResult, dsAsyncResult *model.AsyncDnsMsg) {
	recursion.zone <- DnssecRecursionZone{
		zone:           zone,
		keyAsyncResult: keyAsyncResult,
		dsAsyncResult:  dsAsyncResult,
	}
}

func (recursion DnssecRecursion) RunVerify(rm model.DnsMsg) error {
	recursion.RecurseVerify(0, rm.GetDN(), ".")
	err := recursion.PopVerify(rm)
	return err
}

func (recursion DnssecRecursion) PopVerify(rm model.DnsMsg) error {

	var previousDnsKeyResponse *model.DnsKeyMsg

	for len(recursion.zone) > 0 {

		zone := <-recursion.zone

		keyResult, err := zone.keyAsyncResult.Result()
		if err != nil {
			return fmt.Errorf("unable to query DNSKEY: %s", err.Error())
		}

		dsResult, err := zone.dsAsyncResult.Result()
		if err != nil {
			return fmt.Errorf("unable to query: %s", err.Error())
		}

		dnsKeyResp := keyResult.AsDnsKeyResponse()
		dsResp := dsResult.AsDsResponse()

		err = recursion.ValidateZone(zone.zone, &dnsKeyResp, &dsResp, previousDnsKeyResponse, recursion.validator.anchors.KeyDigest)
		if err != nil {
			return err
		}

		if zsk := dnsKeyResp.ByKeyTag(rm.GetRRSIG().KeyTag); zsk != nil {
			if err = rm.VerifySig(zsk); err != nil {
				return fmt.Errorf("unable to verify final RRSIG: %s", err.Error())
			}
			t.Logger().Printf("final signature is valid in zone: %s", zone.zone)
			return nil
		}

		previousDnsKeyResponse = &dnsKeyResp
	}

	return fmt.Errorf("unable to find the right DNSKEY that signed the response")
}

func (recursion DnssecRecursion) RecurseVerify(deep int, domain, zone string) {

	t.LogDnssec("******** recurse into zone: %s", zone)

	t.LogDnssec("zone %s : query DNSKEY", zone)
	t.LogDnssec("zone %s : query DS", zone)

	keyAsyncResult := recursion.validator.asyncResolver.Query(zone, dns.TypeDNSKEY)
	dsAsyncResult := recursion.validator.asyncResolver.Query(zone, dns.TypeDS)

	recursion.PushToChan(zone, &keyAsyncResult, &dsAsyncResult)

	// end of recursion
	if domain == zone {
		t.LogDnssec("End of recursion")
		return
	}

	subZone := h.SubZone(domain, deep+1)
	recursion.RecurseVerify(deep+1, domain, subZone)
}

func (recursion DnssecRecursion) ValidateZone(zone string, dnsKeyResp *model.DnsKeyMsg, dsResp *model.DsMsg, parentDnsKeyResp *model.DnsKeyMsg, anchors []model.IanaKeyDigest) error {

	t.LogDnssec("******** validating zone: %s", zone)

	// ------ BEGIN DNSKEY VALIDATION ------

	if dnsKeyResp.IsEmpty() { //_dmarc.<domain>.fr
		return nil
	}

	t.LogDnssec("zone %s : verifying DNSKEY RRSIG", zone)
	if err := dnsKeyResp.VerifyRRSIG(); err != nil {
		return fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
	}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})
	// ------ END DNSKEY VALIDATION ------

	// At this point we know it is a zone (with a DS entry)

	// ------ BEGIN DS DIGEST VALIDATION ------
	if zone == "." {

		if err := dnsKeyResp.VerifyTrustAnchor(anchors); err != nil {
			return fmt.Errorf("unable to match trust anchor: %s", err.Error())
		}
		t.LogDnssec("zone %s : matches DS parent (trust anchor)", zone)

	} else {

		// ------ BEGIN DS VALIDATION ------

		if dsResp.IsEmpty() {
			// invalid zone found with DNSKEY rrset but no DS rrset
			return fmt.Errorf("zone: %s : DNSKEY found but no DS record", zone)
		}

		t.LogDnssec("zone %s : verifying DS RRSIG", zone)
		if err := dsResp.VerifyRRSIG(parentDnsKeyResp); err != nil {
			return fmt.Errorf("zone: %s : invalid DS: %s", zone, err.Error())
		}
		t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})
		// ------ END DS VALIDATION ------

		// ------ BEGIN DS DIGEST VALIDATION ------
		// generate DS from KSK and match against DS value of the previous DS
		ds := dsResp.GetDS()
		if err := model.CompareDsDigest(dnsKeyResp.KSK(), ds.DigestType, ds.Digest); err != nil {
			return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
		}
		t.LogDnssec("zone %s : matches DS parent", zone)
		// ------ END DS DIGEST VALIDATION ------
	}

	return nil
}
