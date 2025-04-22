package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tcpRequest struct {
	fr *tcp.ForwarderRequest
	wq *waiter.Queue
}

func (r *tcpRequest) RemoteAddr() net.Addr {
	addr := r.fr.ID().RemoteAddress
	return &net.TCPAddr{IP: addr.AsSlice(), Port: int(r.fr.ID().RemotePort)}
}

func (r *tcpRequest) LocalAddr() net.Addr {
	addr := r.fr.ID().LocalAddress
	return &net.TCPAddr{IP: addr.AsSlice(), Port: int(r.fr.ID().LocalPort)}
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

func (r *tcpRequest) Reject() {
	r.fr.Complete(true)
}

// summarizeTCP summarizes a TCP packet into a single line for logging
func summarizeTCP(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) string {
	var flags []string
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	if tcp.NS {
		flags = append(flags, "NS")
	}
	// ignore PSH flag

	flagstr := strings.Join(flags, "+")
	return fmt.Sprintf("TCP %v:%d => %v:%d %s - Seq %d - Ack %d - Len %d",
		ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort, flagstr, tcp.Seq, tcp.Ack, len(tcp.Payload))
}
