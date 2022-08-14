package service

import (
	"encoding/xml"
	"golang-dns/internal/model"
	"log"
	"time"
)

func LoadIanaFile(content string) model.IanaAnchors {

	var anchor model.IanaAnchors
	err := xml.Unmarshal([]byte(content), &anchor)
	if err != nil {
		log.Fatal(err)
	}

	anchor.KeyDigest = anchor.KeyDigests(time.Now())

	return anchor
}

// SaveIanaFile applies a time filter to existing keys and save it again to its binary form
func SaveIanaFile(anchor model.IanaAnchors) ([]byte, error) {
	anchor.KeyDigest = anchor.KeyDigests(time.Now())
	b, err := xml.Marshal(anchor)
	return b, err
}
