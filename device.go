package main

import (
	"context"
	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

// code in this file is only used for the "homegrown" TCP and UDP stacks

// copyToDevice copies packets from a channel to a tun device
func copyToDevice(ctx context.Context, dst *water.Interface, src chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-src:
			_, err := dst.Write(packet)
			if err != nil {
				slog.Error("error writing to tun: dropping and continuing...", "bytes", len(packet), "err", err)
			}

			slog.Debug("sending bytes to subprocess", "bytes", len(packet))
		}
	}
}

// readFromDevice parses packets from a tun device and delivers them to the TCP and UDP stacks
func readFromDevice(ctx context.Context, tun *water.Interface, tcpstack *tcpStack, udpstack *udpStack) error {
	// start reading raw bytes from the tunnel device and sending them to the appropriate stack
	buf := make([]byte, 1500)
	for {
		// read a packet (TODO: implement non-blocking read on the file descriptor, check for context cancellation)
		n, err := tun.Read(buf)
		if err != nil {
			slog.Error("error reading a packet from tun, ignoring", "err", err)
			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}

		tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !isTCP && !isUDP {
			continue
		}

		if isTCP {
			slog.Debug("received from subprocess", "summary", summarizeTCP(ipv4, tcp, tcp.Payload))
			tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
		}
		if isUDP {
			slog.Debug("received udp from subprocess", "summary", summarizeUDP(ipv4, udp, udp.Payload))
			udpstack.handlePacket(ipv4, udp, udp.Payload)
		}
	}
}
