package service

import (
	"fmt"
	"github.com/miekg/dns"
	"golang-dns/internal/transverse"
)

type DnsFacade struct {
	resolver  DnsResolver
	validator DnssecValidator
}

func NewDnsFacade(resolver DnsResolver, validator DnssecValidator) DnsFacade {
	var f DnsFacade
	defer transverse.Logger().Printf("%s initialized", &f)
	f.resolver = resolver
	f.validator = validator
	return f
}

func (f DnsFacade) Query(name string, dnsType uint16) ([]dns.RR, error) {

	rr, rrsig, err := f.resolver.Query(name, dnsType)
	if err != nil {
		return rr, err
	}

	if rrsig != nil {
		err = f.validator.VerifySig(rr, rrsig)
		return rr, err
	}

	return rr, nil
}

func (f DnsFacade) QueryValidate(name string, dnsType uint16) ([]dns.RR, error) {

	rr, rrsig, err := f.resolver.Query(name, dnsType)
	if err != nil {
		return rr, err
	}

	if rrsig == nil {
		return rr, fmt.Errorf("no signature")
	}

	err = f.validator.VerifySig(rr, rrsig)
	return rr, err
}

func (_ DnsFacade) String() string {
	return fmt.Sprintf("DnsFacade")
}
