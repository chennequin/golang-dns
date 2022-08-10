package providers

import (
	"fmt"
	"golang-dns/internal/service"
	"golang-dns/internal/service/conf"
)

const (
	ServerNameGoogle     = "dns.google"
	ServerNameQuad9      = "quad9.net"
	ServerNameCloudFlare = "cloudflare-dns.com"
	ServerNameNextDns    = "dns.nextdns.io"

	DnsUrlGoogleA     = "https://8.8.8.8/dns-query"
	DnsUrlGoogleB     = "https://8.8.4.4/dns-query"
	DnsUrlCloudFlareA = "https://1.1.1.1/dns-query"
	DnsUrlCloudFlareB = "https://1.0.0.1/dns-query"
	DnsUrlQuad9       = "https://9.9.9.9/dns-query"
	DnsUrlNextDns     = "https://dns.nextdns.io/%s"
)

type RestProvider func() service.HardenedResty
type DnsResolverProvider func() service.DnsResolver
type DnsResolverParam struct {
	ServerName string
	CertFile   string
	Url        string
}

var pool = []DnsResolverParam{
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleA},
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleB},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareA},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareB},
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9},
}

var google = []DnsResolverParam{
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleA},
	{ServerNameGoogle, conf.GoogleCertFile, DnsUrlGoogleB},
}

var cloudFlare = []DnsResolverParam{
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareA},
	{ServerNameCloudFlare, conf.DigiCertCertFile, DnsUrlCloudFlareB},
}

var quad9 = []DnsResolverParam{
	{ServerNameQuad9, conf.DigiCertCertFile, DnsUrlQuad9},
}

func NewDnsPool() []service.DnsResolver {
	return NewDnsResolverPool(pool)
}

func NewGoogleDnsPool() []service.DnsResolver {
	return NewDnsResolverPool(google)
}

func NewCloudFlareDnsPool() []service.DnsResolver {
	return NewDnsResolverPool(cloudFlare)
}

func NewQuad9DnsPool() []service.DnsResolver {
	return NewDnsResolverPool(quad9)
}

func NewDnsResolverPool(params []DnsResolverParam) []service.DnsResolver {
	resolvers := make([]service.DnsResolver, len(params))
	for i, p := range params {
		resolvers[i] = service.NewDnsResolverRestyImpl(service.NewHardenedResty(p.ServerName, p.CertFile), p.Url)
	}
	return resolvers
}

/**********/

func NewRestyGoogle() service.HardenedResty {
	return service.NewHardenedResty(ServerNameGoogle, conf.GoogleCertFile)
}

func NewRestyQuad9() service.HardenedResty {
	return service.NewHardenedResty(ServerNameQuad9, conf.DigiCertCertFile)
}

func NewRestyCloudFlare() service.HardenedResty {
	return service.NewHardenedResty(ServerNameCloudFlare, conf.DigiCertCertFile)
}

func NewRestyNextDns() service.HardenedResty {
	return service.NewHardenedResty(ServerNameNextDns, conf.UserTrustCertFile)
}

/**********/

func NewDnsResolverGoogle() service.DnsResolver {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameGoogle, conf.GoogleCertFile), DnsUrlGoogleA)
}

func NewDnsResolverQuad9() service.DnsResolver {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameQuad9, conf.DigiCertCertFile), DnsUrlQuad9)
}

func NewDnsResolverCloudFlare() service.DnsResolver {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameCloudFlare, conf.DigiCertCertFile), DnsUrlCloudFlareA)
}

func NewDnsResolverNextDns(name string) service.DnsResolver {
	return service.NewDnsResolverRestyImpl(service.NewHardenedResty(ServerNameNextDns, conf.UserTrustCertFile), fmt.Sprintf(DnsUrlNextDns, name))
}
