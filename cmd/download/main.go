package main

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io/ioutil"
	"log"
	"strings"
)

const (
	outputDirDns          = "internal/service/conf/dns"
	outputDirCertificates = "internal/service/conf/certificates"
	tmpDir                = "/tmp"

	// lock manually the checksum in git
	ianaRootAnchors = "https://data.iana.org/root-anchors/root-anchors.xml"
	ianaChecksums   = "https://data.iana.org/root-anchors/checksums-sha256.txt"
	ianaHash        = "45336725f9126db810a59896ae93819de743c416262f79c4444042c92e520770"

	// https://pki.goog/repository/
	// GTS CA 1C3
	gts1c3     = "https://pki.goog/repo/certs/gts1c3.pem"
	gts1c3Hash = "23:ec:b0:3e:ec:17:33:8c:4e:33:a6:b4:8a:41:dc:3c:da:12:28:1b:bc:3f:f8:13:c0:58:9d:6c:c2:38:75:22"

	// https://www.digicert.com/kb/digicert-root-certificates.htm
	// DigiCert TLS Hybrid ECC SHA384 2020 CA1
	hybridCa1     = "https://cacerts.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem"
	hybridCa1Hash = "F7:A9:A1:B2:FD:96:4A:3F:26:70:BD:66:8D:56:1F:B7:C5:5D:3A:A9:AB:83:91:E7:E1:69:70:2D:B8:A3:DB:CF"

	// https://www.tbs-certificates.co.uk/FAQ/en/USERTrust_ECC_CA.html
	userTrust     = "http://www.tbs-x509.com/USERTrustECCCertificationAuthority.crt"
	userTrustHash = "4F F4 60 D5 4B 9C 86 DA BF BC FC 57 12 E0 40 0D 2B ED 3F BC 4D 4F BD AA 86 E0 6A DC D2 A9 AD 7A"
)

// Download DNSSEC Trust Anchors files from iana.org website.
// Download root certificates for all implemented DNS resolvers.
func main() {

	type DigestAssertion struct {
		expect string
		actual string
	}

	downloadSave(ianaRootAnchors, outputDirDns)
	downloadSave(ianaChecksums, tmpDir)
	downloadSave(gts1c3, outputDirCertificates)
	downloadSave(hybridCa1, outputDirCertificates)
	downloadSave(userTrust, outputDirCertificates)

	anchors := fileName(ianaRootAnchors)
	m := newIanaChecksum(readFile(fileName(ianaChecksums), tmpDir))

	log.Println("verifying checksums ...")

	var hashes = []DigestAssertion{
		{fingerPrint(ianaHash), sha256(readFile(anchors, outputDirDns))},
		{fingerPrint(m[anchors]), sha256(readFile(anchors, outputDirDns))},
		{fingerPrint(gts1c3Hash), readCert(gts1c3)},
		{fingerPrint(hybridCa1Hash), readCert(hybridCa1)},
		{fingerPrint(userTrustHash), readCert(userTrust)},
	}

	for _, v := range hashes {
		if v.expect != v.actual {
			log.Println(fmt.Sprintf("invalid checksum found: %s", v.expect))
			log.Println(fmt.Sprintf("expect: %s", v.expect))
			log.Println(fmt.Sprintf("actual: %s", v.actual))
			log.Fatal("INVALID FILES")
		}
	}

	log.Println("FILES ARE VALID")
}

func fingerPrint(sha string) string {
	sha = strings.ReplaceAll(sha, ":", "")
	sha = strings.ReplaceAll(sha, " ", "")
	sha = strings.ToUpper(sha)
	return sha
}

func readCert(name string) string {
	return sha256(fromBase64(stripPEM(readFile(fileName(name), outputDirCertificates))))
}

func downloadSave(url, outputDir string) {

	log.Println(fmt.Sprintf("downloading %s", url))

	_, err := resty.New().
		SetOutputDirectory(outputDir).
		R().
		SetOutput(fileName(url)).
		Get(url)

	if err != nil {
		log.Fatal(fmt.Sprintf("unable to download: %s", err.Error()))
	}
}

func fileName(url string) string {
	parts := strings.Split(url, "/")
	name := parts[len(parts)-1]
	return name
}

func stripPEM(pem []byte) string {
	p := string(pem)
	p = strings.Replace(p, "-----BEGIN CERTIFICATE-----", "", 1)
	p = strings.Replace(p, "-----END CERTIFICATE-----", "", 1)
	return p
}

func readFile(name, outputDir string) []byte {
	file := fmt.Sprintf("%s/%s", outputDir, name)
	b, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func fromBase64(content string) []byte {
	b, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func sha256(content []byte) string {
	s := crypto.SHA256.New()
	s.Write(content)
	digest := hex.EncodeToString(s.Sum(nil))
	digest = strings.ToUpper(digest)
	return digest
}

func newIanaChecksum(content []byte) map[string]string {

	m := make(map[string]string)

	lines := strings.Split(string(content), "\n")
	for _, l := range lines {
		if l == "" {
			continue
		}
		a := strings.Split(l, "  ")
		m[a[1]] = a[0]
	}

	return m
}
