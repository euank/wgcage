package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// This file contains a "homegrown" TCP stack, which is only used with the --stack=homegrown command line argument.

// udpStack parses UDP packets with gopacket and dispatches them through a mux
type udpStack struct {
	toSubprocess chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet
	buf          gopacket.SerializeBuffer
	app          *mux
}

func newUDPStack(app *mux, link chan []byte) *udpStack {
	return &udpStack{
		toSubprocess: link,
		buf:          gopacket.NewSerializeBuffer(),
		app:          app,
	}
}

func (s *udpStack) handlePacket(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) {
	replyudp := layers.UDP{
		SrcPort: udp.DstPort,
		DstPort: udp.SrcPort,
	}

	replyipv4 := layers.IPv4{
		Version:  4, // indicates IPv4
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    ipv4.DstIP,
		DstIP:    ipv4.SrcIP,
	}

	w := udpStackResponder{
		stack:      s,
		udpheader:  &replyudp,
		ipv4header: &replyipv4,
	}

	// forward the data to application-level listeners
	slog.Debug(fmt.Sprintf("got %d udp bytes to %v:%v, delivering to application", len(udp.Payload), ipv4.DstIP, udp.DstPort))

	src := net.UDPAddr{IP: ipv4.SrcIP, Port: int(udp.SrcPort)}
	dst := net.UDPAddr{IP: ipv4.DstIP, Port: int(udp.DstPort)}

	slog.Debug(fmt.Sprintf("udp delivery for homegrown stack not implemented"))

	_ = src
	_ = dst
	_ = w
	// s.app.notifyUDP(&w, &udpPacket{&src, &dst, payload})
}

// serializeUDP serializes a UDP packet
func serializeUDP(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte, tmp gopacket.SerializeBuffer) ([]byte, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tmp.Clear()

	// each layer is *prepended*, treating the current buffer data as payload
	p, err := tmp.AppendBytes(len(payload))
	if err != nil {
		return nil, fmt.Errorf("error appending TCP payload to packet (%d bytes): %w", len(payload), err)
	}
	copy(p, payload)

	err = udp.SerializeTo(tmp, opts)
	if err != nil {
		return nil, fmt.Errorf("error serializing TCP part of packet: %w", err)
	}

	err = ipv4.SerializeTo(tmp, opts)
	if err != nil {
		slog.Error("error serializing IP part of packet", "err", err)
	}

	return tmp.Bytes(), nil
}

// summarizeUDP summarizes a UDP packet into a single line for logging
func summarizeUDP(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) string {
	return fmt.Sprintf("UDP %v:%d => %v:%d - Len %d",
		ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort, len(udp.Payload))
}

// udpStackResponder writes UDP packets back to a known sender
type udpStackResponder struct {
	stack      *udpStack
	udpheader  *layers.UDP
	ipv4header *layers.IPv4
}

func (r *udpStackResponder) SetSourceIP(ip net.IP) {
	r.ipv4header.SrcIP = ip
}

func (r *udpStackResponder) SetSourcePort(port uint16) {
	r.udpheader.SrcPort = layers.UDPPort(port)
}

func (r *udpStackResponder) SetDestIP(ip net.IP) {
	r.ipv4header.DstIP = ip
}

func (r *udpStackResponder) SetDestPort(port uint16) {
	r.udpheader.DstPort = layers.UDPPort(port)
}

func (r *udpStackResponder) Write(payload []byte) (int, error) {
	// set checksums and lengths
	r.udpheader.SetNetworkLayerForChecksum(r.ipv4header)

	// log
	slog.Debug(fmt.Sprintf("sending udp packet to subprocess: %s", summarizeUDP(r.ipv4header, r.udpheader, payload)))

	// serialize the data
	packet, err := serializeUDP(r.ipv4header, r.udpheader, payload, r.stack.buf)
	if err != nil {
		return 0, fmt.Errorf("error serializing UDP packet: %w", err)
	}

	// make a copy because the same buffer will be re-used
	cp := make([]byte, len(packet))
	copy(cp, packet)

	// send to the subprocess channel non-blocking
	select {
	case r.stack.toSubprocess <- cp:
	default:
		return 0, fmt.Errorf("channel for sending udp to subprocess would have blocked")
	}

	// return number of bytes passed in, not number of bytes sent to output
	return len(payload), nil
}
