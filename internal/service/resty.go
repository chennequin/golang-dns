package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	h "golang-dns/internal/helpers"
	t "golang-dns/internal/transverse"
)

type HardenedResty struct {
	client     *resty.Client
	serverName string
}

func NewHardenedResty(serverName, rootCertPemFile string) HardenedResty {
	var rt HardenedResty
	defer t.Logger().Printf("%s initialized", &rt)
	rt.client = newSecureClient(serverName, rootCertPemFile)
	rt.serverName = serverName
	return rt
}

func newSecureClient(serverName, rootCertPemFile string) *resty.Client {
	client := resty.New().
		SetRetryCount(t.GetRetry()).
		SetRedirectPolicy(resty.NoRedirectPolicy()).
		SetTLSClientConfig(&tls.Config{
			ServerName:             serverName,
			MinVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: false,
			InsecureSkipVerify:     false,
			VerifyConnection: func(state tls.ConnectionState) error {

				if err := h.VerifyConnection(serverName, state); err != nil {
					return err
				}

				if state.OCSPResponse != nil {
					if err := h.VerifyOcsp(state); err != nil {
						return err
					}
				}

				return nil
			},
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if t.FlagLogHttpsCerts {
					h.LogPeerCertificate(rawCerts, verifiedChains)
				}
				return nil
			},
		})

	client.SetRootCertificateFromString(rootCertPemFile)

	if t.FlagHttpEnableTrace {
		client.EnableTrace()
	}

	return client
}

func (rt HardenedResty) Client() *resty.Client {
	return rt.client
}

func (rt HardenedResty) String() string {
	return fmt.Sprintf("HardenedResty name=\"%s\" + rootCertificate", rt.serverName)
}

//TODO
// Resolver optionally specifies an alternate resolver to use.
//Resolver *Resolver

// If Control is not nil, it is called after creating the network
// connection but before actually dialing.
//
// Network and address parameters passed to Control method are not
// necessarily the ones passed to Dial. For example, passing "tcp" to Dial
// will cause the Control function to be called with "tcp4" or "tcp6".
//Control func(network, address string, c syscall.RawConn) error
