package model

import "fmt"

type AsyncDnsResponse struct {
	c   chan DnsResponse
	err error
}

func NewAsyncDnsResponse() AsyncDnsResponse {
	return AsyncDnsResponse{
		c: make(chan DnsResponse),
	}
}

func (r AsyncDnsResponse) Push(resp DnsResponse, err error) {
	r.c <- resp
	r.err = err
}

func (r AsyncDnsResponse) Result() (DnsResponse, error) {
	return <-r.c, r.err
}

func (r AsyncDnsResponse) String() string {
	return fmt.Sprintf("AsyncDnsResponse result: %d", len(r.c))
}
