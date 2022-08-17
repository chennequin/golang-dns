package model

import "fmt"

type AsyncDnsMsg struct {
	c   chan DnsMsg
	err error
}

func NewAsyncDnsMsg() AsyncDnsMsg {
	return AsyncDnsMsg{
		c: make(chan DnsMsg),
	}
}

func (r AsyncDnsMsg) Push(resp DnsMsg, err error) {
	r.c <- resp
	r.err = err
}

func (r AsyncDnsMsg) Result() (DnsMsg, error) {
	return <-r.c, r.err
}

func (r AsyncDnsMsg) String() string {
	return fmt.Sprintf("AsyncDnsMsg result: %d", len(r.c))
}
