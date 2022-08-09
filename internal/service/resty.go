package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"golang-dns/internal/helpers"
	"golang-dns/internal/transverse"
	"io/ioutil"
)

type HardenedResty struct {
	client     *resty.Client
	serverName string
}

type DnsHardenedResty struct {
	client     *resty.Client
	serverName string
}

func NewHardenedResty(serverName, rootCertificateFile string) HardenedResty {
	var r HardenedResty
	defer transverse.Logger().Printf("%s initialized", &r)
	r.client = newSecureClient(serverName, rootCertificateFile)
	r.serverName = serverName
	return r
}

func newSecureClient(serverName, rootCertificateFile string) *resty.Client {
	client := resty.New().
		SetRetryCount(transverse.GetRetry()).
		SetRedirectPolicy(resty.NoRedirectPolicy()).
		SetTLSClientConfig(&tls.Config{
			ServerName:             serverName,
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: false,
			InsecureSkipVerify:     false,
			VerifyConnection: func(state tls.ConnectionState) error {

				if err := helpers.VerifyConnection(serverName, state); err != nil {
					return err
				}

				if state.OCSPResponse != nil {
					if err := helpers.VerifyOcsp(state); err != nil {
						return err
					}
				}

				return nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if transverse.FlagLogHttpsCerts {
					helpers.LogPeerCertificate(rawCerts, verifiedChains)
				}
				return nil
			},
		})

	rootPemData, err := ioutil.ReadFile(rootCertificateFile)
	if err != nil {
		transverse.Logger().Fatalf("PEM file not found: %s", err.Error())
	}

	client.SetRootCertificateFromString(string(rootPemData))

	if transverse.FlagHttpEnableTrace {
		client.EnableTrace()
	}

	return client
}

func (r HardenedResty) Client() *resty.Client {
	return r.client
}

func (r HardenedResty) String() string {
	return fmt.Sprintf("HardenedResty name=\"%s\" + rootCertificate", r.serverName)
}
