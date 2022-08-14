package providers

import (
	"github.com/go-resty/resty/v2"
	"golang-dns/internal/transverse"
	"net/http"
	"strings"
	"testing"
)

func TestRestyAll(t *testing.T) {

	//TODO:  verify all resty from pools

	transverse.SetTest()

	// TODO replace those tests with a dns resolver instead

	// thus avoiding using http.StatusBadRequest or http.StatusNotFound
	tests := []struct {
		provider RestProvider
		url      string
		status   int
	}{
		{NewRestyGoogle, "https://dns.google", http.StatusOK},
		{NewRestyCloudFlare, "https://cloudflare-dns.com", http.StatusOK},
		{NewRestyQuad9, "https://9.9.9.9", http.StatusNotFound},
		{NewRestyNextDns, "https://dns.nextdns.io", http.StatusBadRequest},
	}

	errors := []struct {
		provider RestProvider
		url      string
		msg      string
	}{
		{NewRestyGoogle, "https://cloudflare-dns.com", "certificate"},
		{NewRestyGoogle, "https://9.9.9.9", "certificate"},
		{NewRestyGoogle, "https://dns.nextdns.io", "certificate"},
		{NewRestyCloudFlare, "https://dns.google", "certificate"},
		{NewRestyCloudFlare, "https://9.9.9.9", "certificate"},
		{NewRestyCloudFlare, "https://dns.nextdns.io", "certificate"},
		{NewRestyQuad9, "https://dns.google", "certificate"},
		{NewRestyQuad9, "https://cloudflare-dns.com", "certificate"},
		{NewRestyQuad9, "https://dns.nextdns.io", "certificate"},
		{NewRestyNextDns, "https://dns.google", "certificate"},
		{NewRestyNextDns, "https://cloudflare-dns.com", "certificate"},
		{NewRestyNextDns, "https://9.9.9.9", "certificate"},
	}

	for _, tt := range tests {
		var resp *resty.Response
		var err error
		r := tt.provider()
		resp, err = r.Client().R().Get(tt.url)
		ValidateResponseOk(t, resp, err, tt.status)
	}

	for _, tt := range errors {
		var resp *resty.Response
		var err error
		r := tt.provider()
		resp, err = r.Client().R().Get(tt.url)
		ValidateRespBadCert(t, resp, err, tt.msg)
	}

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
		t.Fatalf("expect 'certificate' error")
	}
}
