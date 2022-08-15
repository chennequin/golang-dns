package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	h "golang-dns/internal/helpers"
	t "golang-dns/internal/transverse"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type HardenedResty struct {
	client     *resty.Client
	serverName string
}

func NewHardenedResty(serverName, rootCertPemFile string, ip net.IP) HardenedResty {
	var rt HardenedResty
	defer t.Logger().Printf("%s initialized", &rt)
	rt.serverName = serverName
	rt.client = rt.newRestyClient(serverName, rootCertPemFile, ip)
	return rt
}

func (rt HardenedResty) newRestyClient(serverName, rootCertPemFile string, ip net.IP) *resty.Client {
	client := resty.NewWithClient(createHttpClient(ip)).
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

func createHttpTransport(ip net.IP) *http.Transport {

	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial:         nil,
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
		Resolver:  &resolver,
		Control: func(network, address string, c syscall.RawConn) error {
			if !strings.HasPrefix(network, "tcp4") {
				return fmt.Errorf("only TCP/IPv4 allowed")
			}
			if !(address == fmt.Sprintf("%s:443", ip)) {
				return fmt.Errorf("unauthorized connection to %s", address)
			}
			return nil
		},
	}

	return &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return nil, nil // enforce no proxy
		},
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
	}
}

func createHttpClient(ip net.IP) *http.Client {

	client := http.Client{
		Transport: createHttpTransport(ip),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirect are fordbidden")
		},
		Jar:     nil, // no cookies for DNS queries
		Timeout: 30 * time.Second,
	}

	return &client
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
