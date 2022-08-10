package model

import (
	"encoding/xml"
	"golang-dns/internal/service/conf"
	"log"
	"time"
)

type TrustAnchors struct {
	KeyDigest []KeyDigest `xml:"KeyDigest"`
}

func (a TrustAnchors) KeyDigests(t time.Time) []KeyDigest {
	arr := make([]KeyDigest, 0, 2)
	for _, k := range a.KeyDigest {
		if k.validityPeriod(t) {
			arr = append(arr, k)
		}
	}
	return arr
}

type KeyDigest struct {
	Text       string    `xml:",chardata"`
	ID         string    `xml:"id,attr"`
	ValidFrom  time.Time `xml:"validFrom,attr"`
	ValidUntil time.Time `xml:"validUntil,attr"`
	KeyTag     uint16    `xml:"KeyTag"`
	Algorithm  uint8     `xml:"Algorithm"`
	DigestType uint8     `xml:"DigestType"`
	Digest     string    `xml:"Digest"`
}

func (k KeyDigest) validityPeriod(t time.Time) bool {
	if k.ValidUntil.Year() == 1 {
		return t.After(k.ValidFrom)
	}
	return t.After(k.ValidFrom) && t.Before(k.ValidUntil)
}

func LoadTrustAnchors() []KeyDigest {
	return LoadTrustAnchorFromFile(conf.TrustAnchorFile())
}

func LoadTrustAnchorFromFile(content string) []KeyDigest {

	var anchor TrustAnchors
	err := xml.Unmarshal([]byte(content), &anchor)
	if err != nil {
		log.Fatal(err)
	}

	keys := anchor.KeyDigests(time.Now())

	return keys
}
