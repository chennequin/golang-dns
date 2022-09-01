package service

import (
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
	"time"
)

type DnsLog struct {
	DnsResolverProxyBase
	resolver DnsResolverProxy
}

func NewDnsLog(resolver DnsResolverProxy) DnsResolverProxy {
	var rsv DnsLog
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)
	rsv.resolver = resolver
	return &rsv
}

func (rsv DnsLog) Proxy(m model.DnsMsg) (model.DnsMsg, error) {

	start := time.Now()
	msg, err := rsv.resolver.Proxy(m)

	defer func() {
		elapsed := time.Since(start).Round(1 * time.Millisecond)
		q := m.GetQuestion()

		if msg.IsRRSIG() {
			transverse.Logger().Printf("%s +dnssec %s", elapsed, q.String())
			return
		}

		transverse.Logger().Printf("%s %s", elapsed, q.String())
	}()

	return msg, err
}

func (rsv DnsLog) String() string {
	return fmt.Sprintf("DnsLog")
}
