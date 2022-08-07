package main

import (
	"fmt"
	"github.com/miekg/dns"
	"golang-dns/internal/service"
	"log"
)

func main() {

	//dig @9.9.9.9 dnssec-failed.org a +dnssec

	//url := "https://1.1.1.1/dns-query"
	//url := "https://9.9.9.9/dns-query"
	//url := "https://8.8.8.8/dns-query"
	url := "https://dns.nextdns.io/d11752"

	//name := "icourrier.fr"
	//dnsType := dns.TypeA

	name := "_dmarc.icourrier.fr"
	dnsType := dns.TypeTXT

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dnsType)

	b, err := m.Pack()
	if err != nil {
		log.Fatal(err)
	}

	//r := service.NewHardenedResty("dns.google", "certificates/google/gts1c3.pem")
	//r := service.NewHardenedResty("quad9.net", "certificates/digicert/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem")
	//r := service.NewHardenedResty("cloudflare-dns.com", "certificates/digicert/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem")
	r := service.NewHardenedResty("dns.nextdns.io", "certificates/USERTrust/USERTrustECCCertificationAuthority.pem")

	resp, err := r.Client().R().
		EnableTrace().
		SetHeader("Content-Type", "application/dns-message").
		SetBody(b).
		Post(url)
	if err != nil {
		log.Fatal(err)
	}

	mr := new(dns.Msg)
	err = mr.Unpack(resp.Body())
	if err != nil {
		log.Fatal(err)
	}

	println(fmt.Sprintf("%+v", mr))
}
