// echoapp is the private application the real-environment tests put in the cluster: a TCP echo
// server that logs the address of every client, so a test can see who reached it.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	addr := flag.String("listen", ":7000", "listen address")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("echoapp listening on %s", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("conn from %s\n", c.RemoteAddr())
		go func() { io.Copy(c, c); c.Close() }()
	}
}
