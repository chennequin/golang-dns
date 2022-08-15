package service

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
	"net"
	"net/http"
	"strings"
	"testing"
)

func NewResty() HardenedResty {
	return NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8))
}

func TestHardenedResty(t *testing.T) {

	transverse.SetTest()

	var resp *resty.Response
	var err error

	resp, err = NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)).
		Client().R().Get("https://dns.google")
	ValidateResponseOk(t, resp, err, http.StatusOK)

	resp, err = NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(8, 8, 8, 8)).
		Client().R().Get("https://cloudflare-dns.com")
	ExpectEmptyBody(t, resp)
	ExpectErr(t, err, "unauthorized connection")

	resp, err = NewHardenedResty("dns.google", conf.GoogleCertFile, net.IPv4(9, 9, 9, 9)).
		Client().R().Get("https://9.9.9.9")
	ExpectEmptyBody(t, resp)
	ExpectErr(t, err, "certificate is valid for *.quad9.net, quad9.net, not dns.google")

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

func ExpectEmptyBody(t *testing.T, resp *resty.Response) {
	if len(resp.Body()) != 0 {
		t.Fatalf("response is not empty: %v", resp)
	}
}

func ExpectErr(t *testing.T, err error, expected string) {
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf(fmt.Sprintf("expect '%s' error", expected))
	}
}
