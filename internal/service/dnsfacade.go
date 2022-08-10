package service

import (
	"fmt"
	"golang-dns/internal/service/model"
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

func (f DnsFacade) Query(name string, dnsType uint16) (model.DnsResponse, error) {

	r, err := f.resolver.Query(name, dnsType)
	if err != nil {
		return r, err
	}

	if r.IsRRSIG() {
		err = f.validator.Verify(r)
		return r, err
	}

	return r, nil
}

func (f DnsFacade) QueryValidate(name string, dnsType uint16) (model.DnsResponse, error) {

	r, err := f.resolver.Query(name, dnsType)
	if err != nil {
		return r, err
	}

	if r.IsRRSIG() {
		return r, fmt.Errorf("no signature")
	}

	err = f.validator.Verify(r)
	return r, err
}

func (_ DnsFacade) String() string {
	return fmt.Sprintf("DnsFacade")
}
