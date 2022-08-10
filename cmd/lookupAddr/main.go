package main

import (
	"fmt"
	"net"
)

func main() {
	names, err := net.LookupAddr("8.8.8.8")
	if err != nil {
		panic(err)
	}
	if len(names) == 0 {
		fmt.Printf("no record")
	}
	for _, name := range names {
		fmt.Printf("%s\n", name)
	}
}
