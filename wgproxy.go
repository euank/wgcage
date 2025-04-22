package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wireguardProxy struct {
	dev  *device.Device
	tnet *netstack.Net
}

func newWgProxy(ourIP, privateKey, pubKey string, endpoint string) (*wireguardProxy, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(ourIP)},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1500,
	)
	if err != nil {
		return nil, err
	}
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid priv key: %w", err)
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid priv key: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(0, "[WG]"))

	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
endpoint=%s`, hex.EncodeToString(privKeyBytes), hex.EncodeToString(pubKeyBytes), endpoint))
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return &wireguardProxy{
		dev:  dev,
		tnet: tnet,
	}, nil
}

func (wg *wireguardProxy) ProxyConn(network, addr string, subprocess net.Conn) {
	conn, err := wg.tnet.Dial(network, addr)
	if err != nil {
		// TODO: report errors not related to destination being unreachable
		subprocess.Close()
		return
	}
	go proxyBytes(subprocess, conn)
	go proxyBytes(conn, subprocess)
}
