package model

import (
	"github.com/miekg/dns"
	"time"
)

type IanaAnchors struct {
	KeyDigest []IanaKeyDigest `xml:"KeyDigest"`
}

func (a IanaAnchors) KeyDigests(t time.Time) []IanaKeyDigest {
	arr := make([]IanaKeyDigest, 0, 2)
	for _, k := range a.KeyDigest {
		if k.validityPeriod(t) {
			arr = append(arr, k)
		}
	}
	return arr
}

type IanaKeyDigest struct {
	ValidFrom  time.Time `xml:"validFrom,attr"`
	ValidUntil time.Time `xml:"validUntil,attr"`
	KeyTag     uint16    `xml:"KeyTag"`
	Algorithm  uint8     `xml:"Algorithm"`
	DigestType uint8     `xml:"DigestType"`
	Digest     string    `xml:"Digest"`
}

func (k IanaKeyDigest) validityPeriod(t time.Time) bool {
	if k.ValidUntil.Year() == 1 {
		return t.After(k.ValidFrom)
	}
	return t.After(k.ValidFrom) && t.Before(k.ValidUntil)
}

func (k IanaKeyDigest) ToDS() *dns.DS {
	return &dns.DS{
		Hdr:        dns.RR_Header{},
		KeyTag:     k.KeyTag,
		Algorithm:  k.Algorithm,
		DigestType: k.DigestType,
		Digest:     k.Digest,
	}
}
