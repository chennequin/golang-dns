package helpers

import (
	"github.com/miekg/dns"
	"strings"
)

func Msg(name string, dnsType uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(name), dnsType)
	m.SetEdns0(4096, true)
	return m
}

func CollectAll(rrset []dns.RR, dnsType uint16) []dns.RR {
	dnsKeys := make([]dns.RR, 0, 10)
	for _, v := range rrset {
		if v.Header().Rrtype == dnsType {
			dnsKeys = append(dnsKeys, v)
		}
	}
	return dnsKeys
}

func CollectOne(rrset []dns.RR, dnsType uint16) dns.RR {
	for _, v := range rrset {
		if v.Header().Rrtype == dnsType {
			return v
		}
	}
	return nil
}

func AsDnsKeyMap(rrset []dns.RR) map[uint16]*dns.DNSKEY {
	dnsKeysMap := make(map[uint16]*dns.DNSKEY, 2)
	for _, v := range rrset {
		if t, ok := v.(*dns.DNSKEY); ok {
			dnsKeysMap[t.KeyTag()] = t
		}
	}
	return dnsKeysMap
}

func SubZone(domain string, i int) string {

	if i == 0 {
		return "."
	}

	arr := strings.Split(domain, ".")

	builder := strings.Builder{}

	for j := i; j > 0; j-- {
		begin := len(arr) - j - 1
		if begin < 0 {
			return "" // sub-zone does not exists
		}
		builder.WriteString(arr[begin:][0])
		builder.WriteString(".")
	}

	return builder.String()
}
