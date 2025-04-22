package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tcpRequest struct {
	fr *tcp.ForwarderRequest
	wq *waiter.Queue
}

func (r *tcpRequest) Accept() (net.Conn, error) {
	ep, err := r.fr.CreateEndpoint(r.wq)
	if err != nil {
		r.fr.Complete(true)
		return nil, fmt.Errorf("CreateEndpoint: %v", err)
	}

	// TODO: set keepalive count, keepalive interval, receive buffer size, send buffer size, like this:
	//   https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L83

	// create an adapter that makes a gvisor endpoint into a net.Conn
	conn := gonet.NewTCPConn(r.wq, ep)
	r.fr.Complete(false)
	return conn, nil
}
