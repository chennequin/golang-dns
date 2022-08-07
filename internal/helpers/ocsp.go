package helpers

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/ocsp"
)

func VerifyOcspBinary(b []byte, issuerCert *x509.Certificate) error {

	ocspResponse, err := ocsp.ParseResponse(b, issuerCert)

	if err != nil {
		return fmt.Errorf("OCSP: unable to parse OCSP response: %s", err.Error())
	}

	if ocspResponse.Status != ocsp.Good {
		return fmt.Errorf("OCSP: invalid OCSP status: %d", ocspResponse.Status)
	}

	return nil
}

func VerifyOCSP(clientCert, issuerCert *x509.Certificate) error {

	if len(clientCert.OCSPServer) < 1 {
		return fmt.Errorf("must provide at least one OCSP server")
	}
	ocspServer := clientCert.OCSPServer[0]

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	b, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return fmt.Errorf("unable to create OCSP request: %s", err.Error())
	}

	resp, err := resty.New().R().
		SetHeader("Content-Type", "application/ocsp-request").
		SetHeader("Accept", "application/ocsp-response").
		SetHeader("Content-Type", "application/dns-message").
		SetBody(b).Post(ocspServer)

	if err != nil {
		return fmt.Errorf("OCSP request error: %s", err.Error())
	}

	if err := VerifyOcspBinary(resp.Body(), issuerCert); err != nil {
		return err
	}

	return nil
}
