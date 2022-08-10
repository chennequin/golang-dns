package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/service/model"
	t "golang-dns/internal/transverse"
	"sync"
)

const (
	capacity = 10
)

type ZoneDB struct {
	aDS     []model.DsResponse
	aDNSKEY []model.DnsKeyResponse
}

func NewZoneDB() ZoneDB {
	return ZoneDB{
		aDS:     make([]model.DsResponse, capacity),
		aDNSKEY: make([]model.DnsKeyResponse, capacity),
	}
}

type DnssecValidator struct {
	resolver DnsResolver
	anchors  []model.IanaKeyDigest
}

func NewDnssecValidator(resolver DnsResolver) DnssecValidator {
	return NewDnssecValidatorFromIanaFile(resolver, LoadIanaFile(conf.IanaFile()))
}

func NewDnssecValidatorFromIanaFile(resolver DnsResolver, anchors []model.IanaKeyDigest) DnssecValidator {
	var v DnssecValidator
	defer t.Logger().Printf("%s initialized", &v)
	v.resolver = resolver
	v.anchors = anchors
	return v
}

func (s DnssecValidator) Verify(r model.DnsResponse) error {

	db := NewZoneDB()

	if err := s.TopDownPrepareBase(r.GetDN(), db); err != nil {
		return fmt.Errorf("signature is invalid: %s", err)
	}

	if err := s.TopDownVerifyBase(r, db); err != nil {
		return fmt.Errorf("signature is invalid: %s", err.Error())
	}

	t.Logger().Printf("signature is valid.")

	return nil
}

func (s DnssecValidator) TopDownPrepareBase(domain string, db ZoneDB) error {

	wg := &sync.WaitGroup{}
	c := make(chan error, 10)

	s.TopDownPrepare(wg, c, 0, domain, ".", db)

	wg.Wait()

	if len(c) < 0 {
		return <-c
	}
	return nil
}

// TopDownPrepare retrieves DS and DNSKEY of all zones starting from zone "."
// Uses go routines in //. Builds DB.
func (s DnssecValidator) TopDownPrepare(wg *sync.WaitGroup, c chan error, deep int, domain, zone string, db ZoneDB) {

	//TODO here: avoid querying _dmarc.*.fr. DS / DNSKEY if RRSIG validates DNSKEY of parent zone

	getFn := func(zone string, dnsType uint16) model.DnsResponse {
		rk, err := s.resolver.Query(zone, dnsType)
		if err != nil {
			c <- fmt.Errorf("zone: %s : unable to query: %s", zone, err.Error())
		}
		return rk
	}

	go func() {
		defer wg.Done()

		// obtaining the ZSK and KSK for the zone
		db.aDNSKEY[deep] = getFn(zone, dns.TypeDNSKEY).AsDNSKEY()
	}()
	wg.Add(1)

	if zone == "." {
		goto nextZone
	}

	go func() {
		defer wg.Done()

		// obtaining DS for the zone
		db.aDS[deep] = getFn(zone, dns.TypeDS).AsDS()
	}()
	wg.Add(1)

	if domain == zone {
		return
	}

nextZone:
	subZone := h.SubZone(domain, deep+1)
	s.TopDownPrepare(wg, c, deep+1, domain, subZone, db)
}

// TopDownVerifyBase validates the trust chain starting from zone "."
// Single go routine. All Data are in DB.
func (s DnssecValidator) TopDownVerifyBase(r model.DnsResponse, db ZoneDB) error {
	return s.TopDownVerify(0, r.GetDN(), ".", nil, r, db)
}

func (s DnssecValidator) TopDownVerify(deep int, domain, zone string, parentDnsKeys *model.DnsKeyResponse, r model.DnsResponse, db ZoneDB) error {

	if domain == zone {
		// verify original RR signature
		// the var. 'domain' is NOT a DNS zone
		// ex: _dmarc.afnic.fr
		if recEnd, err := r.FindVerifySig(parentDnsKeys); recEnd {
			return err
		}
	}

	// obtaining the ZSK and KSK for the zone
	dnsKey := db.aDNSKEY[deep]

	if err := dnsKey.VerifyRRSIG(); err != nil {
		return fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
	}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})

	var ds model.DsResponse

	if zone == "." {

		if err := dnsKey.VerifyTrustAnchor(s.anchors); err != nil {
			return fmt.Errorf("unable to match trust anchor: %s", err.Error())
		}

		t.LogDnssec("zone %s : trust anchor matches", zone)

		goto nextZone

	}

	if domain == zone {
		// verify original RR signature
		// the var. 'domain' IS a DNS zone
		// ex: afnic.fr
		_, err := r.FindVerifySig(&dnsKey)
		return err
	}

	// obtaining DS for the zone
	ds = db.aDS[deep]

	if err := ds.Verify(&dnsKey, parentDnsKeys); err != nil {
		return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
	}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})

nextZone:

	subZone := h.SubZone(domain, deep+1)
	return s.TopDownVerify(deep+1, domain, subZone, &dnsKey, r, db)
}

func (_ DnssecValidator) String() string {
	return fmt.Sprintf("DnssecValidator")
}
