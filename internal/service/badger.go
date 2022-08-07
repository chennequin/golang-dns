package service

import (
	"crypto/x509"
	"fmt"
	"golang-dns/internal/transverse"
)

type BadgerService struct {
}

func NewBadgerService() BadgerService {
	var b BadgerService
	defer transverse.Logger().Printf("%s initialized", &b)
	return b
}

func (s BadgerService) Store(cert *x509.Certificate) error {

	_ = cert.Issuer.CommonName
	_ = cert.Subject.CommonName

	return nil
}

func (_ BadgerService) String() string {
	return fmt.Sprintf("BadgerService")
}
