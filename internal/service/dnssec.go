package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/service/model"
	t "golang-dns/internal/transverse"
	"sync"
	"time"
)

type DnssecValidator struct {
	resolver    DnsResolver
	trustAnchor dns.DNSKEY
}

func NewDnssecValidator(resolver DnsResolver, trustAnchor dns.DNSKEY) DnssecValidator {
	var v DnssecValidator
	defer t.Logger().Printf("%s initialized", &v)
	v.resolver = resolver
	v.trustAnchor = trustAnchor
	return v
}

func (s DnssecValidator) VerifySig(r model.DnsResponse) error {

	wg := &sync.WaitGroup{}
	lock := sync.Mutex{}
	c := make(chan error, 10)
	m := make(map[string]model.DnsResponse, 10)

	s.TopDownPrepare(lock, wg, c, 0, r.GetDN(), ".", m)
	wg.Wait()

	if len(c) < 0 {
		return fmt.Errorf("signature is invalid: %s", <-c)
	}

	err := s.TopDownVerifySig(0, r.GetDN(), ".", nil, r, m)

	if err != nil {
		return fmt.Errorf("signature is invalid: %s", err.Error())
	}

	t.Logger().Printf("signature is valid.")

	return err
}

func MapKey(zone string, dnsType uint16) string {
	return fmt.Sprintf("%s/%d", zone, dnsType)
}

func (s DnssecValidator) TopDownPrepare(lock sync.Mutex, wg *sync.WaitGroup, c chan error, deep int, domain, zone string, m map[string]model.DnsResponse) {

	go func() {
		// obtaining the ZSK and KSK for the zone
		rk, err := s.resolver.Query(zone, dns.TypeDNSKEY)
		if err != nil {
			c <- fmt.Errorf("zone: %s : unable to obtain DNSKEY: %s", zone, err.Error())
		}
		lock.Lock()
		defer lock.Unlock()
		m[MapKey(zone, dns.TypeDNSKEY)] = rk
		wg.Done()
	}()
	wg.Add(1)

	if zone == "." {
		goto nextZone
	}

	go func() {
		// obtaining DS for the zone
		rds, err := s.resolver.Query(zone, dns.TypeDS)
		if err != nil {
			c <- fmt.Errorf("zone: %s : unable to obtain DS: %s", zone, err.Error())
		}
		lock.Lock()
		defer lock.Unlock()
		m[MapKey(zone, dns.TypeDS)] = rds
		wg.Done()
	}()
	wg.Add(1)

	if domain == zone {
		return
	}

nextZone:
	subZone := h.SubZone(domain, deep+1)
	s.TopDownPrepare(lock, wg, c, deep+1, domain, subZone, m)
}

func (s DnssecValidator) TopDownVerifySig(deep int, domain, zone string, kkMapParentZone map[uint16]*dns.DNSKEY, r model.DnsResponse, m map[string]model.DnsResponse) error {

	if domain == zone {
		// verify original RR signature
		// the var. 'domain' is NOT a DNS zone
		// ex: _dmarc.afnic.fr
		if recEnd, err := s.VerifyEntrySig(kkMapParentZone, r); recEnd {
			return err
		}
	}

	// obtaining the ZSK and KSK for the zone
	rk := m[MapKey(zone, dns.TypeDNSKEY)]

	ksk, kkMap, err := s.VerifyZoneKeys(rk)
	if err != nil {
		return fmt.Errorf("zone: %s : unable to validate DNSKEY: %s", zone, err.Error())
	}

	var rds model.DnsResponse

	if zone == "." {

		if err := s.verifyTrustAnchor(ksk); err != nil {
			return fmt.Errorf("unable to validate root KSK againts the trust anchor: %s", err.Error())
		}

		t.LogDnssec("zone %s : trust anchor matches %T", zone, ksk)

		goto nextZone

	}

	if domain == zone {
		// verify original RR signature
		// the var. 'domain' IS a DNS zone
		// ex: _dmarc.afnic.fr
		_, err = s.VerifyEntrySig(kkMap, r)
		return err
	}

	// obtaining DS for the zone
	rds = m[MapKey(zone, dns.TypeDS)]

	if err = s.verifyDS(rds, ksk, kkMapParentZone); err != nil {
		return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
	}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})

nextZone:

	subZone := h.SubZone(domain, deep+1)

	return s.TopDownVerifySig(deep+1, domain, subZone, kkMap, r, m)
}

// VerifyEntrySig verifies that the specified rrset a valid signature against the specified key set.
// returns true if the key has been found in the map, false otherwise.
func (s DnssecValidator) VerifyEntrySig(kkMap map[uint16]*dns.DNSKEY, r model.DnsResponse) (bool, error) {

	rrset := r.GetRR()
	rrsig := r.GetRRSIG()
	rrk := kkMap[rrsig.KeyTag]

	if rrk != nil {
		if err := s.verifySig(rrset, rrsig, rrk); err != nil {
			return true, fmt.Errorf("invalid RR/RRSIG: %s", err.Error())
		}
		return true, nil
	}

	return false, nil
}

// VerifyZoneKeys verifies DNSKEY signature of the specified zone.
// returns the KSK and a map of the keys.
func (s DnssecValidator) VerifyZoneKeys(rk model.DnsResponse) (*dns.DNSKEY, map[uint16]*dns.DNSKEY, error) {

	kkset := rk.GetDNSKEY()
	kksig := rk.GetRRSIG()
	kkMap := h.AsDnsKeyMap(kkset)

	if kksig == nil {
		return nil, nil, fmt.Errorf("no RRSIG for DNSKEY")
	}

	// find the KSK of zone
	ksk := kkMap[kksig.KeyTag]

	// verify DNSKEY signature
	if err := s.verifySig(kkset, kksig, ksk); err != nil {
		return ksk, kkMap, fmt.Errorf("invalid DNSKEY: %s", err.Error())
	}

	t.LogDnssec("%T signature: valid", &dns.DNSKEY{})

	return ksk, kkMap, nil
}

// verifyDS verifies DS integrity for the specified zone given the zone KSK and parent zone KSK
func (s DnssecValidator) verifyDS(r model.DnsResponse, ksk *dns.DNSKEY, kkMapParentZone map[uint16]*dns.DNSKEY) error {

	rrset := r.GetRR()
	rrsig := r.GetRRSIG()
	rrk := kkMapParentZone[rrsig.KeyTag]

	if err := s.verifySig(rrset, rrsig, rrk); err != nil {
		return fmt.Errorf("invalid DS: %s", err.Error())
	}

	if err := s.verifyDSHash(r.GetDS(), ksk); err != nil {
		return fmt.Errorf("invalid DS: %s", err.Error())
	}

	return nil
}

// verifySig verifies signature of the given RRSET, RRSIG against the specified DNSKEY
func (_ DnssecValidator) verifySig(rrset []dns.RR, rrsig *dns.RRSIG, ksk *dns.DNSKEY) error {

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

// verifyDSHash verifies the hash of specified DS against the specified KSK
func (_ DnssecValidator) verifyDSHash(ds *dns.DS, ksk *dns.DNSKEY) error {

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

// verifyTrustAnchor compares the specified key with the trust anchor
func (s DnssecValidator) verifyTrustAnchor(kk *dns.DNSKEY) error {

	if kk.KeyTag() != s.trustAnchor.KeyTag() ||
		kk.Flags != s.trustAnchor.Flags ||
		kk.Algorithm != s.trustAnchor.Algorithm ||
		kk.Protocol != s.trustAnchor.Protocol {
		return fmt.Errorf("keys are different")
	}

	return nil
}

func (_ DnssecValidator) String() string {
	return fmt.Sprintf("DnssecValidator")
}
