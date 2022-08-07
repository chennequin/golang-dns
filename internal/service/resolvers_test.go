package service

import (
	"github.com/go-resty/resty/v2"
	"golang-dns/internal/transverse"
	"net/http"
	"testing"
)

func TestRestyAll(t *testing.T) {

	transverse.SetTest()

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
