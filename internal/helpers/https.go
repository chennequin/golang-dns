package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/go-resty/resty/v2"
	t "golang-dns/internal/transverse"
)

func LogPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) {
	println("***************************")
	for _, chain := range verifiedChains {
		for _, cert := range chain {
			t.Logger().Println("-----BEGIN CERTIFICATE-----")
			t.Logger().Println(fmt.Sprintf("DNSNames: %v", cert.DNSNames))
			t.Logger().Println(fmt.Sprintf("IPAddresses: %v", cert.IPAddresses))
			t.Logger().Println(fmt.Sprintf("IssuingCertificateURL: %v", cert.IssuingCertificateURL))
			t.Logger().Println(fmt.Sprintf("OCSPServer: %v", cert.OCSPServer))
			t.Logger().Println(fmt.Sprintf("Issuer: %v", cert.Issuer))
			t.Logger().Println(fmt.Sprintf("Subject: %v", cert.Subject))
			t.Logger().Println(fmt.Sprintf("NotBefore: %v", cert.NotBefore))
			t.Logger().Println(fmt.Sprintf("NotAfter: %v", cert.NotAfter))
			t.Logger().Println("-----END CERTIFICATE-----")
		}
	}
	println("***************************")
}

func LogTrace(resp *resty.Response, err error) {

	println("***************************")

	fmt.Println("Response Info:")
	fmt.Println("  Error      :", err)
	fmt.Println("  Status Code:", resp.StatusCode())
	fmt.Println("  Status     :", resp.Status())
	fmt.Println("  Proto      :", resp.Proto())
	fmt.Println("  Time       :", resp.Time())
	fmt.Println("  Received At:", resp.ReceivedAt())
	fmt.Println("  Body       :", base64.StdEncoding.EncodeToString(resp.Body()))
	fmt.Println()

	fmt.Println("Request Trace Info:")
	ti := resp.Request.TraceInfo()
	fmt.Println("  DNSLookup     :", ti.DNSLookup)
	fmt.Println("  ConnTime      :", ti.ConnTime)
	fmt.Println("  TCPConnTime   :", ti.TCPConnTime)
	fmt.Println("  TLSHandshake  :", ti.TLSHandshake)
	fmt.Println("  ServerTime    :", ti.ServerTime)
	fmt.Println("  ResponseTime  :", ti.ResponseTime)
	fmt.Println("  TotalTime     :", ti.TotalTime)
	fmt.Println("  IsConnReused  :", ti.IsConnReused)
	fmt.Println("  IsConnWasIdle :", ti.IsConnWasIdle)
	fmt.Println("  ConnIdleTime  :", ti.ConnIdleTime)
	fmt.Println("  RequestAttempt:", ti.RequestAttempt)
	fmt.Println("  RemoteAddr    :", ti.RemoteAddr.String())

	println("***************************")
}

func VerifyCipherSuite(cipherSuite uint16) error {

	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == cipherSuite {
			return fmt.Errorf("insecure cipher suite used: %s", cs.Name)
		}
	}

	// allow only TLS 1.3 cipher suites
	for _, cs := range tls.CipherSuites() {
		if cs.ID == cipherSuite {
			if len(cs.SupportedVersions) == 1 && cs.SupportedVersions[0] == tls.VersionTLS13 {
				t.Logger().Printf("using cipher suite %s\n", cs.Name)
				return nil
			}
		}
	}

	return fmt.Errorf("unauthorised cipher suite used: %d", cipherSuite)
}

func VerifyConnection(serverName string, state tls.ConnectionState) error {

	if state.NegotiatedProtocol != "h2" {
		return fmt.Errorf("VerifyConnection: HTTP/2 is required")
	}

	if state.ServerName != serverName {
		return fmt.Errorf("VerifyConnection: bad server name found: %s", state.ServerName)
	}

	if len(state.VerifiedChains) != 1 {
		return fmt.Errorf("VerifyConnection: too many verified chains")
	}

	if err := VerifyCipherSuite(state.CipherSuite); err != nil {
		return fmt.Errorf("VerifyConnection: %s", err.Error())
	}

	return nil
}

func VerifyOcsp(state tls.ConnectionState) error {
	chain := state.VerifiedChains[0]
	issuerCert := chain[1]
	return VerifyOcspBinary(state.OCSPResponse, issuerCert)
}
