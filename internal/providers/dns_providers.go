package providers

import (
	"fmt"
	"golang-dns/internal/service"
	"golang-dns/internal/service/conf"
	"net"
)

const (
	ServerNameGoogle     = "dns.google"
	ServerNameQuad9      = "quad9.net"
	ServerNameCloudFlare = "cloudflare-dns.com"
)

var (
	IpGoogleA     = net.IPv4(8, 8, 8, 8)
	IpGoogleB     = net.IPv4(8, 8, 4, 4)
	IpCloudFlareA = net.IPv4(1, 1, 1, 1)
	IpCloudFlareB = net.IPv4(1, 0, 0, 1)
	IpQuad9A      = net.IPv4(9, 9, 9, 9)
	IpQuad9B      = net.IPv4(149, 112, 112, 112)

	DnsUrlGoogleA     = fmt.Sprintf("https://%s/dns-query", IpGoogleA)
	DnsUrlGoogleB     = fmt.Sprintf("https://%s/dns-query", IpGoogleB)
	DnsUrlCloudFlareA = fmt.Sprintf("https://%s/dns-query", IpCloudFlareA)
	DnsUrlCloudFlareB = fmt.Sprintf("https://%s/dns-query", IpCloudFlareB)
	DnsUrlQuad9A      = fmt.Sprintf("https://%s/dns-query", IpQuad9A)
	DnsUrlQuad9B      = fmt.Sprintf("https://%s/dns-query", IpQuad9B)
)

type DnsResolverParam struct {
	ServerName string
	CertFile   string
	Url        string
	ip         net.IP
}

var globalPool = []DnsResolverParam{
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleA, IpGoogleA},
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleB, IpGoogleB},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareA, IpCloudFlareA},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareB, IpCloudFlareB},
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9A, IpQuad9A},
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9B, IpQuad9B},
}

var googlePool = []DnsResolverParam{
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleA, IpGoogleA},
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleB, IpGoogleB},
}

var cloudFlarePool = []DnsResolverParam{
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareA, IpCloudFlareA},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareB, IpCloudFlareB},
}

var quad9Pool = []DnsResolverParam{
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9A, IpQuad9A},
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9B, IpQuad9B},
}

type DnsPool struct {
	resolvers []service.DnsResolverProxy
}

func NewGlobalDnsPool() service.DnsResolverProxy {
	return service.NewDnsResolverPoolImpl(NewDnsResolverPool(globalPool...)...)
}

func NewGoogleDnsPool() service.DnsResolverProxy {
	return service.NewDnsResolverPoolImpl(NewDnsResolverPool(googlePool...)...)
}

func NewCloudFlareDnsPool() service.DnsResolverProxy {
	return service.NewDnsResolverPoolImpl(NewDnsResolverPool(cloudFlarePool...)...)
}

func NewQuad9DnsPool() service.DnsResolverProxy {
	return service.NewDnsResolverPoolImpl(NewDnsResolverPool(quad9Pool...)...)
}

func NewDnsResolverPool(params ...DnsResolverParam) []service.DnsResolverProxy {
	resolvers := make([]service.DnsResolverProxy, len(params))
	for i, p := range params {
		resolvers[i] = service.NewDnsResolverRestyImpl(service.NewHardenedResty(p.ServerName, p.CertFile, p.ip), p.Url)
	}
	return resolvers
}

/**********/

func NewRestyGoogle() service.HardenedResty {
	return service.NewHardenedResty(ServerNameGoogle, conf.GoogleCertFile, IpGoogleA)
}

func NewRestyQuad9() service.HardenedResty {
	return service.NewHardenedResty(ServerNameQuad9, conf.DigiCertCertFile, IpQuad9A)
}

func NewRestyCloudFlare() service.HardenedResty {
	return service.NewHardenedResty(ServerNameCloudFlare, conf.DigiCertCertFile, IpCloudFlareA)
}

/**********/

func NewDnsResolverGoogle() service.DnsResolverProxy {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameGoogle, conf.GoogleCertFile, IpGoogleA), DnsUrlGoogleA)
}

func NewDnsResolverQuad9() service.DnsResolverProxy {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameQuad9, conf.DigiCertCertFile, IpQuad9A), DnsUrlQuad9A)
}

func NewDnsResolverCloudFlare() service.DnsResolverProxy {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameCloudFlare, conf.DigiCertCertFile, IpCloudFlareA), DnsUrlCloudFlareA)
}
