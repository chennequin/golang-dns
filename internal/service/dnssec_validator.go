package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/service/conf"
	t "golang-dns/internal/transverse"
	"strings"
	"time"
)

const (
	nonBlockingChannel = 10
)

type DnssecValidator struct {
	resolver      DnsResolverProxy
	asyncResolver AsyncDnsResolver
	anchors       model.IanaAnchors
}

func NewDnssecValidator(resolver DnsResolverProxy) DnssecValidator {
	return NewDnssecValidatorFromIanaFile(resolver, LoadIanaFile(conf.IanaFile))
}

func NewDnssecValidatorFromIanaFile(resolver DnsResolverProxy, anchors model.IanaAnchors) DnssecValidator {
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
	dn := rm.GetRrsigDN()
	recursion.Recurse(0, dn, ".")
	err := recursion.Verify(rm)
	return err
}

func (recursion DnssecRecursion) Verify(rm model.DnsMsg) error {

	var previousDnsKeyResponse model.DnsMsg

	for len(recursion.zone) > 0 {

		zone := <-recursion.zone

		dnsKeyResp, err := zone.keyAsyncResult.Result()
		if err != nil {
			return fmt.Errorf("unable to query DNSKEY: %s", err.Error())
		}

		dsResp, err := zone.dsAsyncResult.Result()
		if err != nil {
			return fmt.Errorf("unable to query DS: %s", err.Error())
		}

		err = recursion.VerifyZone(zone.zone, dnsKeyResp, dsResp, previousDnsKeyResponse, recursion.validator.anchors.KeyDigest)
		if err != nil {
			return err
		}

		if err = VerifySignature(dnsKeyResp, rm); err == nil {
			// found a DNSKEY in that zone which has the KeyTag of the final RRSIG
			// does it verify the RRSIG ?
			t.LogDnssec("final RRSIG is valid in zone: %s", zone.zone)
			return nil
		}

		// if the signature does not verify
		// continue with the next zone ...
		// some subdomains (ex: chrome.cloudflare-dns.com.) reuse the keys of their parents
		// and the final RRSIG will only be valid with the DNSKEY of the final zone.

		previousDnsKeyResponse = dnsKeyResp
	}

	return fmt.Errorf("unable to find the right DNSKEY that signed the response")
}

func (recursion DnssecRecursion) Recurse(deep int, domain, zone string) {

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
	recursion.Recurse(deep+1, domain, subZone)
}

func (recursion DnssecRecursion) VerifyZone(zone string, dnsKeyResp model.DnsMsg, dsResp model.DnsMsg, parentDnsKeyResp model.DnsMsg, anchors []model.IanaKeyDigest) error {

	t.LogDnssec("******** validating zone: %s", zone)

	// ------ BEGIN DNSKEY VALIDATION ------
	t.LogDnssec("zone %s : verifying DNSKEY RRSIG", zone)
	if err := VerifySignature(dnsKeyResp, dnsKeyResp); err != nil {
		return fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
	}
	t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})
	// ------ END DNSKEY VALIDATION ------

	// At this point we know it is a zone (with a DS entry)

	// ------ BEGIN DS DIGEST VALIDATION ------
	if zone == "." {

		if err := VerifyTrustAnchors(dnsKeyResp, anchors); err != nil {
			return fmt.Errorf("unable to match trust anchor: %s", err.Error())
		}
		t.LogDnssec("zone %s : matches DS parent (trust anchor)", zone)

	} else {

		// ------ BEGIN DS VALIDATION ------
		t.LogDnssec("zone %s : verifying DS RRSIG", zone)

		if dsResp.IsEmpty() {
			// check presence of NSEC3
			if err := VerifyNsec3(dsResp, parentDnsKeyResp); err != nil {
				return fmt.Errorf("zone: %s : invalid DS: invalid NSEC3: %s", zone, err.Error())
			}

			// We have proof of non-existence of the DS record
			// hence there is nothing to verify.
			return nil
		}

		if err := VerifySignature(parentDnsKeyResp, dsResp); err != nil {
			return fmt.Errorf("zone: %s : invalid DS: %s", zone, err.Error())
		}
		t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})
		// ------ END DS VALIDATION ------

		// ------ BEGIN DS DIGEST VALIDATION ------
		// generate DS from KSK and match against DS value
		ds := dsResp.GetDS()
		kk := dnsKeyResp.ByKeyTag(ds.KeyTag)
		if err := VerifyDigest(kk, ds); err != nil {
			return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
		}
		t.LogDnssec("zone %s : matches DS parent", zone)
		// ------ END DS DIGEST VALIDATION ------
	}

	return nil
}

func VerifyNsec3(m model.DnsMsg, parentDnsKeyResp model.DnsMsg) error {

	nsec3 := m.GetNSEC3()
	name := m.GetQuestion().Name

	if len(nsec3) == 0 {
		return fmt.Errorf("no NSEC3 record found")
	}

	// An NSEC3 record that *matches* the "closest encloser".
	encloser := FindClosestEncloser(0, ".", name, m.GetNSEC3())
	if encloser == "" {
		return fmt.Errorf(fmt.Sprintf("NSEC3 does not matche closest encloser: %s", encloser))
	}
	t.LogDnssec(fmt.Sprintf("NSEC3 matches closest encloser: %s", encloser))

	// An NSEC3 record that *covers* the "next closer name".
	{
		if !Nsec3Covers(name, nsec3) {
			return fmt.Errorf(fmt.Sprintf("NSEC3 does not cover next closer name: %s", encloser))
		}
		t.LogDnssec(fmt.Sprintf("NSEC3 covers next closer name: %s", name))
	}

	// "*.<closest encloser>"
	{
		wildCard := "*." + encloser
		if len(nsec3) > 2 && !Nsec3Covers(wildCard, nsec3) {
			return fmt.Errorf(fmt.Sprintf("NSEC3 does not covers wildcard: %s", wildCard))
		}
		t.LogDnssec(fmt.Sprintf("NSEC3 covers wildcard: %s", wildCard))
	}

	// verify signatures of Authority Section
	var currentRR dns.RR
	for _, v := range m.GetMsg().Ns {

		if rrsig, ok := v.(*dns.RRSIG); ok {
			kk := parentDnsKeyResp.ByKeyTag(rrsig.KeyTag)

			if err := VerifySig(kk, rrsig, []dns.RR{currentRR}); err != nil {
				return fmt.Errorf("invalid key found: %s", err.Error())
			}
			continue
		}

		currentRR = v
	}

	return nil
}

func Nsec3Covers(name string, nsec3 []*dns.NSEC3) bool {
	for _, v := range nsec3 {
		if v.Cover(name) {
			return true
		}
	}
	return false
}

func FindClosestEncloser(deep int, zone, initial string, nsec3 []*dns.NSEC3) string {

	if len(nsec3) > 0 && nsec3[0].Match(zone) {
		return zone
	}

	if zone == initial {
		return ""
	}

	subZone := h.SubZone(initial, deep+1)
	return FindClosestEncloser(deep+1, subZone, initial, nsec3)
}

// VerifyTrustAnchors compares DNSKEY(s) with the specified trust anchors
func VerifyTrustAnchors(m model.DnsMsg, anchors []model.IanaKeyDigest) error {

	for _, a := range anchors {
		for _, rrsig := range m.GetRRSIG() {

			ksk := m.ByKeyTag(rrsig.KeyTag)
			ds := a.ToDS()

			if err := VerifyDigest(ksk, ds); err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("unable to match trust anchor")
}

// VerifyDigest calculates the DS digest of the specified key and compares with the specified digest
func VerifyDigest(ksk *dns.DNSKEY, ds *dns.DS) error {

	if ksk == nil {
		return fmt.Errorf("must provide ksk")
	}

	if ds == nil {
		return fmt.Errorf("must provide ds")
	}

	// calculate DS hash using zone KSK
	calc := strings.ToUpper(ksk.ToDS(ds.DigestType).Digest)

	// compares with the expected Digest
	expected := strings.ToUpper(ds.Digest)
	if calc != expected {
		return fmt.Errorf("invalid digest hash")
	}

	return nil
}

func VerifySignature(keys model.DnsMsg, m model.DnsMsg) error {

	if m.IsEmpty() {
		return fmt.Errorf("answer is empty: %s", m)
	}

	signatures := m.GetRRSIG()
	if len(signatures) == 0 {
		return fmt.Errorf("no signature: %s", m)
	}

	for _, rrsig := range signatures {

		kk := keys.ByKeyTag(rrsig.KeyTag)
		rr := m.GetRR()

		if err := VerifySig(kk, rrsig, rr); err != nil {
			return fmt.Errorf("invalid key found: %s", err.Error())
		}
	}

	return nil
}

// VerifySig verifies signature of the given RRSET, RRSIG against the specified DNSKEY set
func VerifySig(ksk *dns.DNSKEY, rrsig *dns.RRSIG, rrset []dns.RR) error {

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
		return fmt.Errorf("invalid RRSIG: keyTag: %d: %s", rrsig.KeyTag, err.Error())
	}

	if !rrsig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("invalid RRSIG period: keyTag: %d", rrsig.KeyTag)
	}

	return nil
}
