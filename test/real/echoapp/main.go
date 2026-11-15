// echoapp is the private application the real-environment tests put in the cluster: a TCP echo
// server that logs the address of every client, so a test can see who reached it.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/larytet/zscaler/internal/logx"
)

func main() {
	addr := flag.String("listen", ":7000", "listen address")
	flag.Parse()
	logx.Setup("echoapp")
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logx.Die(err)
	}
	slog.Info("echoapp listening", "addr", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			logx.Die(err)
		}
		fmt.Printf("conn from %s\n", c.RemoteAddr())
		go func() { io.Copy(c, c); c.Close() }()
	}
}
