package server

import (
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"golang-dns/internal/model"
	"golang-dns/internal/service"
	"io/ioutil"
	"net/http"
)

func StartGin(resolver service.DnsResolverProxy) {

	r := gin.Default()
	r.POST("/dns-query", HandleDnsQuery(resolver))

	_ = r.Run("127.0.0.1:8080")
}

func HandleDnsQuery(resolver service.DnsResolverProxy) gin.HandlerFunc {
	return func(c *gin.Context) {

		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Data(http.StatusBadRequest, "application/dns-message", body)
			return
		}

		m := new(dns.Msg)
		err = m.Unpack(body)
		if err != nil {
			c.Data(http.StatusBadRequest, "application/dns-message", body)
			return
		}

		r, err := resolver.Proxy(model.NewDnsMsg(m))

		output, err := r.GetMsg().Pack()
		if err != nil {
			c.Data(http.StatusBadRequest, "application/dns-message", body)
			return
		}

		c.Data(http.StatusOK, "application/dns-message", output)

	}
}
