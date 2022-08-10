package main

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io/ioutil"
	"log"
	"strings"
)

const (
	outputDir = "internal/service/conf/dns"
	tmpDir    = "/tmp"

	rootAnchors = "https://data.iana.org/root-anchors/root-anchors.xml"
	checksums   = "https://data.iana.org/root-anchors/checksums-sha256.txt"

	// lock manually the checksum in git
	hashManual = "45336725f9126db810a59896ae93819de743c416262f79c4444042c92e520770"
)

// Download DNSSEC Trust Anchors files from iana.org website.
func main() {

	DownloadSave(rootAnchors, outputDir)
	DownloadSave(checksums, tmpDir)

	checksum := fileName(checksums)
	anchors := fileName(rootAnchors)

	log.Println("verifying checksums ...")

	m := newChecksum(readTextFile(checksum, tmpDir))

	hashDeclared := m[anchors]
	hashFile := sha256(readTextFile(anchors, outputDir))

	if hashFile != hashDeclared || hashFile != hashManual {
		log.Fatal("INVALID FILES")
	}

	log.Println("FILES ARE VALID")
}

func DownloadSave(url, outputDir string) {

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

func readTextFile(name, outputDir string) string {
	file := fmt.Sprintf("%s/%s", outputDir, name)
	b, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

func sha256(content string) string {
	s := crypto.SHA256.New()
	s.Write([]byte(content))
	digest := hex.EncodeToString(s.Sum(nil))
	return digest
}

func newChecksum(content string) map[string]string {

	m := make(map[string]string)

	lines := strings.Split(content, "\n")
	for _, l := range lines {
		if l == "" {
			continue
		}
		a := strings.Split(l, "  ")
		m[a[1]] = a[0]
	}

	return m
}
