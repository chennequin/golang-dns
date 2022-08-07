package service

import (
	"fmt"
	"golang-dns/internal/service/conf"
	"golang-dns/internal/transverse"
)

type RestProvider func() HardenedResty
type DnsResolverProvider func() DnsResolver

func NewRestyGoogle() HardenedResty {
	return NewHardenedResty(conf.ServerNameGoogle, transverse.GetPath()+conf.RootCertificateGoogle)
}

func NewRestyQuad9() HardenedResty {
	return NewHardenedResty(conf.ServerNameQuad9, transverse.GetPath()+conf.RootCertificateQuad9)
}

func NewRestyCloudFlare() HardenedResty {
	return NewHardenedResty(conf.ServerNameCloudFlare, transverse.GetPath()+conf.RootCertificateCloudFlare)
}

func NewRestyNextDns() HardenedResty {
	return NewHardenedResty(conf.ServerNameNextDns, transverse.GetPath()+conf.RootCertificateNextDns)
}

func NewDnsResolverGoogle() DnsResolver {
	return NewDnsResolverRestyImpl(NewRestyGoogle(), conf.DnsUrlGoogle)
}

func NewDnsResolverQuad9() DnsResolver {
	return NewDnsResolverRestyImpl(NewRestyQuad9(), conf.DnsUrlQuad9)
}

func NewDnsResolverCloudFlare() DnsResolver {
	return NewDnsResolverRestyImpl(NewRestyCloudFlare(), conf.DnsUrlCloudFlare)
}

func NewDnsResolverNextDns(name string) DnsResolver {
	return NewDnsResolverRestyImpl(NewRestyNextDns(), fmt.Sprintf(conf.DnsUrlNextDns, name))
}
