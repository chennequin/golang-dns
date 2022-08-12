package service

import (
	"encoding/xml"
	"golang-dns/internal/model"
	"log"
	"time"
)

func LoadIanaFile(content string) []model.IanaKeyDigest {

	var anchor model.IanaAnchors
	err := xml.Unmarshal([]byte(content), &anchor)
	if err != nil {
		log.Fatal(err)
	}

	keys := anchor.KeyDigests(time.Now())

	return keys
}
