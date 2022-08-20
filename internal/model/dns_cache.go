package model

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"strconv"
	"strings"
)

type DnsCacheKey string

func (e DnsCacheKey) Decode() (string, uint16) {
	r := strings.Split(string(e), "/")
	dn := r[0]
	dnsType, _ := strconv.Atoi(r[1])
	return dn, uint16(dnsType)
}

func NewDnsCacheKey(name string, dnsType uint16) string {
	return fmt.Sprintf("%s/%d", name, dnsType)
}

/********************/

type DnsRistrettoEntry struct {
	name     string
	dnsType  uint16
	response DnsMsg
}

func (e DnsRistrettoEntry) Value() DnsMsg {
	return e.response
}

func (e DnsRistrettoEntry) String() string {
	return fmt.Sprintf("{m:%v}", e.response.GetMsg())
}

func NewDnsRistrettoEntry(r DnsMsg) DnsRistrettoEntry {
	return DnsRistrettoEntry{
		response: r,
	}
}

/********************/

type DnsBadgerEntry struct {
	name    string
	dnsType uint16
	msg     dns.Msg
}

func (e DnsBadgerEntry) String() string {
	return fmt.Sprintf("{m:%v}", e.msg)
}

func (e DnsBadgerEntry) AsBytes() ([]byte, error) {
	return json.Marshal(e.msg)
}

func NewDnsBadgerEntry(m *dns.Msg) DnsBadgerEntry {
	return DnsBadgerEntry{
		msg: *m,
	}
}
