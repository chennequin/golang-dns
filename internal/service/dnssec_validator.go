package service

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"golang-dns/internal/model"
	"golang-dns/internal/service/conf"
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
	resolver      DnsResolver
	asyncResolver AsyncDnsResolver
	anchors       []model.IanaKeyDigest
}

func NewDnssecValidator(resolver DnsResolver) DnssecValidator {
	return NewDnssecValidatorFromIanaFile(resolver, LoadIanaFile(conf.IanaFile))
}

func NewDnssecValidatorFromIanaFile(resolver DnsResolver, anchors []model.IanaKeyDigest) DnssecValidator {
	var v DnssecValidator
	defer t.Logger().Printf("%s initialized", &v)
	v.resolver = resolver
	v.asyncResolver = NewAsyncDnsResolverImpl(resolver)
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
		db.aDNSKEY[deep] = getFn(zone, dns.TypeDNSKEY).AsDnsKeyResponse()
	}()
	wg.Add(1)

	if zone == "." {
		goto nextZone
	}

	go func() {
		defer wg.Done()

		// obtaining DS for the zone
		db.aDS[deep] = getFn(zone, dns.TypeDS).AsDsResponse()
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

	var wg sync.WaitGroup
	var dsc = make(chan *dns.DS, 10)
	var zsk = make(chan *model.DnsKeyResponse, 10)
	var errors = make(chan error, 10)

	param := DnssecRecursionParam{
		wg:     &wg,
		errors: errors,
		dsc:    dsc,
		zsk:    zsk,
	}

	s.AltTopDownVerify(0, r.GetDN(), ".", dsc, param)

	//if _, err := r.FindVerifySig(&dnsKeyResp); err != nil { //_dmarc
	//	errors <- fmt.Errorf("unable to validate final RRSIG: %s", err.Error())
	//}

	return nil
}

func (s DnssecValidator) zzTopDownVerifyBase(errors chan error, r model.DnsResponse, db ZoneDB) error {
	return s.zzTopDownVerify(errors, 0, r.GetDN(), ".", nil, r)
}

func (s DnssecValidator) zzTopDownVerify(errors chan error, deep int, domain, zone string, _ *model.DnsKeyResponse, r model.DnsResponse) error {

	//if domain == zone {
	//	// verify original RR signature
	//	// the var. 'domain' is NOT a DNS zone
	//	// ex: _dmarc.afnic.fr
	//	if recEnd, err := r.FindVerifySig(parentDnsKeys); recEnd {
	//		return err
	//	}
	//}

	// obtaining the ZSK and KSK for the zone
	//db.aDNSKEY[deep] = getFn(zone, dns.TypeDNSKEY).AsDnsKeyResponse()
	var c chan model.AsyncDnsResponse
	go func() {

		async := <-c
		result, err := async.Result()
		if err != nil {
			errors <- fmt.Errorf("zone: %s : unable to query: %s", zone, err.Error())
		}

		dnsKey := result.AsDnsKeyResponse()

		if err := dnsKey.VerifyRRSIG(); err != nil {
			errors <- fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
			return
		}

		t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})

		if zone == "." {

			if err := dnsKey.VerifyTrustAnchor(s.anchors); err != nil {
				errors <- fmt.Errorf("unable to match trust anchor: %s", err.Error())
				return
			}

			t.LogDnssec("zone %s : trust anchor matches", zone)
			goto out
		}

		if domain == zone {
			// verify original RR signature
			// the var. 'domain' IS a DNS zone
			// ex: afnic.fr
			_, err := r.FindVerifySig(&dnsKey)
			if err != nil {
				errors <- err
			}
		}

	out:
	}()

	//var ds model.DsResponse

	if zone == "." {
		goto nextZone
	}

	//s.asyncResolver.Query(zone, dns.TypeDNSKEY, c)

	//dnsKey := db.aDNSKEY[deep]

	//if err := dnsKey.VerifyRRSIG(); err != nil {
	//	return fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
	//}
	//
	//t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})

	//var ds model.DsResponse

	//if zone == "." {
	//
	//	if err := dnsKey.VerifyTrustAnchor(s.anchors); err != nil {
	//		return fmt.Errorf("unable to match trust anchor: %s", err.Error())
	//	}
	//
	//	t.LogDnssec("zone %s : trust anchor matches", zone)
	//
	//	goto nextZone
	//
	//}

	//if domain == zone {
	//	// verify original RR signature
	//	// the var. 'domain' IS a DNS zone
	//	// ex: afnic.fr
	//	_, err := r.FindVerifySig(&dnsKey)
	//	return err
	//}

	// obtaining DS for the zone
	//ds = db.aDS[deep]
	//
	//if err := ds.Verify(&dnsKey, parentDnsKeys); err != nil {
	//	return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
	//}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})

nextZone:

	subZone := h.SubZone(domain, deep+1)

	if domain == subZone {
		// verify original RR signature
		// the var. 'domain' is NOT a DNS zone
		// ex: _dmarc.afnic.fr
		//if recEnd, err := r.FindVerifySig(dnsKey); recEnd {
		//	return err
		//}
	}

	return s.zzTopDownVerify(errors, deep+1, domain, subZone, nil, r)
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

	if err := ds.VerifyRRSIG(parentDnsKeys); err != nil {
		return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
	}

	if err := model.CompareDsDigest(dnsKey.KSK(), ds.GetDS().DigestType, ds.GetDS().Digest); err != nil {
		return fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
	}

	t.LogDnssec("zone %s : %T : valid", zone, &dns.DS{})

nextZone:

	subZone := h.SubZone(domain, deep+1)
	return s.TopDownVerify(deep+1, domain, subZone, &dnsKey, r, db)
}

type DnssecRecursionParam struct {
	wg     *sync.WaitGroup
	errors chan error
	dsc    chan *dns.DS
	zsk    chan *model.DnsKeyResponse
}

func (rp DnssecRecursionParam) NoErrors() bool {
	return len(rp.errors) == 0
}

func (rp DnssecRecursionParam) HasZSK() bool {
	return len(rp.zsk) > 0
}

func (s DnssecValidator) AltTopDownVerify(deep int, domain, zone string, dsc chan *dns.DS, params DnssecRecursionParam) {

	subZone := h.SubZone(domain, deep+1)
	t.LogDnssec("******** recurse into zone: %s (%s)", zone, subZone)

	params.wg.Add(1)
	go func(wg *sync.WaitGroup, zone, subZone string) {
		defer wg.Done()

		keyAsyncResult := s.asyncResolver.Query(zone, dns.TypeDNSKEY)
		dsAsyncResult := s.asyncResolver.Query(zone, dns.TypeDS) //TODO

		// ------ BEGIN DNSKEY VALIDATION ------
		t.LogDnssec("zone %s : query DNSKEY", zone)
		keyResult, err := keyAsyncResult.Result()
		if err != nil {
			params.errors <- fmt.Errorf("zone %s : unable to query DNSKEY: %s", zone, err.Error())
			return
		}

		dnsKeyResp := keyResult.AsDnsKeyResponse()

		if dnsKeyResp.IsEmpty() { //_dmarc
			return
		}

		t.LogDnssec("zone %s : verifying DNSKEY RRSIG", zone)
		if err := dnsKeyResp.VerifyRRSIG(); err != nil {
			params.errors <- fmt.Errorf("zone: %s : invalid DNSKEY: %s", zone, err.Error())
			return
		}

		t.LogDnssec("zone %s : %T : valid", zone, &dns.DNSKEY{})
		// ------ END DNSKEY VALIDATION ------

		// At this point we know it is a zone (with a DS entry)

		// ------ BEGIN DS DIGEST VALIDATION ------
		if zone == "." {

			if err := dnsKeyResp.VerifyTrustAnchor(s.anchors); err != nil {
				params.errors <- fmt.Errorf("unable to match trust anchor: %s", err.Error())
				return
			}
			t.LogDnssec("zone %s : matches DS parent (trust anchor)", zone)

		} else {
			//fr: 1b3386864d30ccc8f4541b985bf2ca320e4f52c57c53353f6d29c9ad58a5671f
			//icourrier.fr: 8b78b592dd67cfe393629f9a492cc4684259bf92080506cdee215e5fd25685fc
			// get previous DS
			parentDS := <-dsc
			// generate DS from KSK and match against DS value of the previous DS
			if err := model.CompareDsDigest(dnsKeyResp.KSK(), parentDS.DigestType, parentDS.Digest); err != nil {
				params.errors <- fmt.Errorf("zone: %s : unable to validate DS: %s", zone, err.Error())
				return
			}
			t.LogDnssec("zone %s : matches DS parent", zone)
		}
		// ------ END DS DIGEST VALIDATION ------

		if zone == domain { //icourrier
			params.zsk <- &dnsKeyResp
			return
		}

		if subZone == "" {
			println("")
		}

		// ------ BEGIN DS VALIDATION ------
		t.LogDnssec("zone %s : query DS", subZone)
		dsResult, err := dsAsyncResult.Result()
		if err != nil {
			params.errors <- fmt.Errorf("zone: %s : unable to query: %s", subZone, err.Error())
			return
		}

		dsResp := dsResult.AsDsResponse()
		if dsResult.IsEmpty() { //_dmarc
			params.zsk <- &dnsKeyResp
			return
		}

		// send DS digest to channel (once previous check is done in order to guaranty ordering)
		defer func() {
			println(fmt.Sprintf("pushing DS: %s", subZone))
			dsc <- dsResp.GetDS()
		}()

		t.LogDnssec("zone %s : verifying DS RRSIG", subZone)
		if err := dsResp.VerifyRRSIG(&dnsKeyResp); err != nil {
			params.errors <- fmt.Errorf("zone: %s : invalid DS: %s", subZone, err.Error())
			return
		}
		t.LogDnssec("zone %s : %T : valid", subZone, &dns.DS{})
		// ------ END DS VALIDATION ------

		if subZone == "" {
			params.zsk <- &dnsKeyResp
			return
		}

	}(params.wg, zone, subZone)

	// end of recursion
	if domain == zone {
		params.wg.Wait()
		t.LogDnssec("End of recursion")
		return
	}

	s.AltTopDownVerify(deep+1, domain, subZone, dsc, params)
}

func (_ DnssecValidator) String() string {
	return fmt.Sprintf("DnssecValidator")
}
