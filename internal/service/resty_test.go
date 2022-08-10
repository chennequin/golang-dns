package service

import (
	"github.com/go-resty/resty/v2"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
	"net/http"
	"strings"
	"testing"
)

func NewResty() HardenedResty {
	return NewHardenedResty("dns.google", conf.GoogleCertFile)
}

func TestHardenedResty(t *testing.T) {

	transverse.SetTest()

	r := NewResty()
	var resp *resty.Response
	var err error

	resp, err = r.Client().R().Get("https://dns.google")
	ValidateResponseOk(t, resp, err, http.StatusOK)

	resp, err = r.Client().R().Get("https://cloudflare-dns.com")
	ValidateRespBadCert(t, resp, err, "certificate is valid for cloudflare-dns.com, *.cloudflare-dns.com, one.one.one.one, not dns.google")

	resp, err = r.Client().R().Get("https://9.9.9.9")
	ValidateRespBadCert(t, resp, err, "certificate is valid for *.quad9.net, quad9.net, not dns.google")

	resp, err = r.Client().R().Get("https://dns.nextdns.io")
	ValidateRespBadCert(t, resp, err, "certificate signed by unknown authority")

	t.Logf("Success !")
}

func ValidateResponseOk(t *testing.T, resp *resty.Response, err error, status int) {
	if err != nil {
		t.Fatalf("got error %v", err.Error())
	}
	if resp.StatusCode() != status {
		t.Fatalf("got response status %v", resp.Status())
	}
}

func ValidateRespBadCert(t *testing.T, resp *resty.Response, err error, expected string) {
	if len(resp.Body()) != 0 {
		t.Fatalf("response is not empty: %v", resp)
	}
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expect 'certificate name does not match' error")
	}
}
