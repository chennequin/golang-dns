package service

import (
	"context"
	"fmt"
	"golang-dns/internal/model"
	"golang-dns/internal/transverse"
	"golang.org/x/time/rate"
)

const (
	DefaultRateLimit = 20
	DefaultBurst     = 50
)

type DnsRateLimiting struct {
	DnsResolverProxyBase
	resolver DnsResolverProxy
	limiter  *rate.Limiter
}

func NewDnsRateLimiting(resolver DnsResolverProxy) DnsResolverProxy {
	var rsv DnsRateLimiting
	defer transverse.Logger().Printf("%s initialized", &rsv)
	defer rsv.initDnsResolverBase(&rsv)

	rsv.resolver = resolver
	rsv.limiter = rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultBurst)

	return &rsv
}

func (rsv DnsRateLimiting) Proxy(m model.DnsMsg) (model.DnsMsg, error) {

	if err := rsv.limiter.Wait(context.Background()); err != nil {
		return m, fmt.Errorf("too many requests: %s", err.Error())
	}

	msg, err := rsv.resolver.Proxy(m)
	return msg, err
}

func (rsv DnsRateLimiting) String() string {
	return fmt.Sprintf("DnsRateLimiting")
}
