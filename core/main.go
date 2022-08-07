package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
)

const (
	address = "9.9.9.9:53"
)

var client = new(dns.Client)

var trustAnchor = dns.DNSKEY{
	Flags:     257,
	Protocol:  3,
	Algorithm: 8,
	PublicKey: trimAll(
		`AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
			+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv
			ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF
			0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e
			oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd
			RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN
			R1AkUTV74bU=`),
}

func main() {

	domain := "icourrier.fr"

	rr, rrsig, err := MsgExchange(domain, dns.TypeMX)
	err = VerifySig(rr, rrsig)
	if err != nil {
		log.Fatal(err)
	}
}

func MsgExchange(name string, dnsType uint16) ([]dns.RR, *dns.RRSIG, error) {
	m := Msg(name, dnsType)
	in, _, err := Exchange(m)
	if err != nil {
		return nil, nil, err
	}
	if !in.MsgHdr.RecursionAvailable || !in.MsgHdr.AuthenticatedData || in.MsgHdr.CheckingDisabled {
		return nil, nil, fmt.Errorf("not acceptable header received %+v", in.MsgHdr)
	}
	rr := collectAll(in, dnsType)
	rrsig := collectOne(in, dns.TypeRRSIG).(*dns.RRSIG)
	return rr, rrsig, nil
}

func VerifySig(rrset []dns.RR, rrsig *dns.RRSIG) error {
	domain := rrset[0].Header().Name
	return VerifySigRec(domain, rrset, rrsig)
}

func VerifySigRec(zone string, rrset []dns.RR, rrsig *dns.RRSIG) error {

	if rrsig == nil {
		return fmt.Errorf("zone: %s - no signature", zone)
	}

	if !dns.IsRRset(rrset) {
		return fmt.Errorf("zone: %s - invalid rrset provided", zone)
	}

	// obtaining the ZSK and KSK for the zone
	kkArr, kksig, err := MsgExchange(zone, dns.TypeDNSKEY)
	kkMap := asDnsKeyMap(kkArr)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to obtain DNSKEY: %s", zone, err.Error())
	}

	// verify RR signature
	err = rrsig.Verify(kkMap[rrsig.KeyTag], rrset)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to verify RR RRSIG: %s", zone, err.Error())
	}

	if !rrsig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("zone: %s - invalid validity period for RR RRSIG", zone)
	}

	// verify DNSKEY signature
	err = kksig.Verify(kkMap[kksig.KeyTag], kkArr)
	if err != nil {
		return fmt.Errorf("zone: %s - unable to verify DNSKEY RRSIG: %s", zone, err.Error())
	}

	if !kksig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("zone: %s - invalid validity period for DNSKEY RRSIG", zone)
	}

	if zone == "." {
		// this is the end of recursion

		// find the KSK of root zone .
		kk := kkMap[kksig.KeyTag]

		// and compare it with the trust anchor
		if kk.KeyTag() != trustAnchor.KeyTag() ||
			kk.Flags != trustAnchor.Flags ||
			kk.Algorithm != trustAnchor.Algorithm ||
			kk.Protocol != trustAnchor.Protocol {
			return fmt.Errorf("unable to validate trust chain up to the trust anchor")
		}

		return nil
	}

	// obtaining DS for the zone

	dsArr, dssig, err := MsgExchange(zone, dns.TypeDS)
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

	zones := strings.SplitN(zone, ".", 2)
	if len(zones) < 2 {
		return fmt.Errorf("bad recursion")
	}
	parent := dns.Fqdn(zones[1])

	return VerifySigRec(parent, []dns.RR{ds}, dssig)
}

func Msg(name string, dnsType uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(name), dnsType)
	m.SetEdns0(4096, true)
	return m
}

func Exchange(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	in, rtt, err := client.Exchange(m, address)
	println(fmt.Sprintf("rtt=%s", rtt))
	return in, rtt, err
}

func asDnsKeyMap(rrset []dns.RR) map[uint16]*dns.DNSKEY {
	dnsKeysMap := make(map[uint16]*dns.DNSKEY, 2)
	for _, v := range rrset {
		if t, ok := v.(*dns.DNSKEY); ok {
			dnsKeysMap[t.KeyTag()] = t
		}
	}
	return dnsKeysMap
}

func collectAll(m *dns.Msg, dnsType uint16) []dns.RR {
	dnsKeys := make([]dns.RR, 0, 10)
	for _, v := range m.Answer {
		if v.Header().Rrtype == dnsType {
			dnsKeys = append(dnsKeys, v)
		}
	}
	return dnsKeys
}

func collectOne(m *dns.Msg, dnsType uint16) dns.RR {
	for _, v := range m.Answer {
		if v.Header().Rrtype == dnsType {
			return v
		}
	}
	return nil
}

func trimAll(s string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(s,
				" ", ""),
			"\n", ""),
		"\t", "")
}
