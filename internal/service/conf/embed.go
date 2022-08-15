package conf

import (
	_ "embed"
)

//go:embed dns/root-anchors.xml
var IanaFile string

//go:embed certificates/gts1c3.pem
var GoogleCertFile string

//go:embed certificates/DigiCertTLSHybridECCSHA3842020CA1-1.crt.pem
var DigiCertCertFile string
