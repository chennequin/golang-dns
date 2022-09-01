package model

import (
	"fmt"
	"github.com/miekg/dns"
	h "golang-dns/internal/helpers"
	"strconv"
	"strings"
)

type DnsCacheKey string

func (e DnsCacheKey) ToDnsMsg() DnsMsg {

	r := strings.Split(string(e), "/")
	n := r[0]
	t, _ := strconv.Atoi(r[1])
	clazz, _ := strconv.Atoi(r[2])

	msg := NewDnsMsg(h.Msg(n, uint16(t), uint16(clazz)))
	return msg
}

func NewDnsCacheKey(msg DnsMsg) string {
	q := msg.GetQuestion()
	return fmt.Sprintf("%s/%d/%d", q.Name, q.Qtype, q.Qclass)
}

/********************/

type DnsRistrettoEntry struct {
	msg []byte
}

func NewDnsRistrettoEntry(m DnsMsg) (DnsRistrettoEntry, error) {
	var entry DnsRistrettoEntry
	msg, err := m.GetMsg().Pack()
	entry.msg = msg
	return entry, err
}

func (e DnsRistrettoEntry) Value() (DnsMsg, error) {
	in := new(dns.Msg)
	err := in.Unpack(e.msg)
	return NewDnsMsg(in), err
}

/********************/

type DnsBadgerEntry struct {
	msg []byte
}

func NewDnsBadgerEntry(m DnsMsg) (DnsBadgerEntry, error) {
	var entry DnsBadgerEntry
	msg, err := m.GetMsg().Pack()
	entry.msg = msg
	return entry, err
}

func (e DnsBadgerEntry) AsBytes() []byte {
	return e.msg
}
