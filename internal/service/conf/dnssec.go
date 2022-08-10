package conf

import (
	_ "embed"
)

//go:embed dns/root-anchors.xml
var rootAnchorsFile string

func TrustAnchorFile() string {
	return rootAnchorsFile
}
