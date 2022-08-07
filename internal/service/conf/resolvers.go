package conf

const (
	ServerNameGoogle     = "dns.google"
	ServerNameQuad9      = "quad9.net"
	ServerNameCloudFlare = "cloudflare-dns.com"
	ServerNameNextDns    = "dns.nextdns.io"

	RootCertificateGoogle     = "certificates/google/gts1c3.pem"
	RootCertificateQuad9      = "certificates/digicert/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem"
	RootCertificateCloudFlare = "certificates/digicert/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem"
	RootCertificateNextDns    = "certificates/usertrust/USERTrustECCCertificationAuthority.pem"

	DnsUrlGoogle     = "https://8.8.8.8/dns-query"
	DnsUrlQuad9      = "https://9.9.9.9/dns-query"
	DnsUrlCloudFlare = "https://1.1.1.1/dns-query"
	DnsUrlNextDns    = "https://dns.nextdns.io/%s"
)
