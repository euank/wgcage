# wirecage

Force any application to route through a wireguard VPN with no chance of leaks.

No root required (assuming unprivileged user namespaces are enabled).

## Quickstart

You can run any command and force it to route through wireguard.

Want to run firefox through a vpn without affecting your other software? Put it in a wirecage:

```shell
./wirecage \
  --wg-endpoint "<wireguard server endpoint>" \
  --wg-public-key "<base64 wireguard server public key>" \
  --wg-private-key-file "/path/to/wireguard/private/key" \
  --wg-address "<our wireguard ip>" \
  -- firefox
```

Create a profile and browse around, and you'll see that you appear to be coming from your wireguard server's IP :)

You can also run simple tools like curl:

```shell
./wirecage \
  --wg-endpoint "<wireguard server endpoint>" \
  --wg-public-key "<base64 wireguard server public key>" \
  --wg-private-key-file "/path/to/wireguard/private/key" \
  --wg-address "<our wireguard ip>" \
  -- curl -4 https://api.myip.com

{"ip": "<wireguard server ip>"}
```

You can also open a shell and look around:

```shell
wirecage \
  ... \
  bash

# ip addr

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
2: wirecage: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    inet 10.1.2.100/24 brd 10.1.2.255 scope global wirecage
```

As you can see, the only route is to a tun interface, and that interface will
route straight to wireguard, ensuring proper network isolation.

## Ubuntu 23.10 and later

On Ubuntu 23.10 and later you will need to run the following in order to use wirecage:

```shell
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

What this does is disable a [recent kernel feature that restricts unpriveleged user namespaces](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces).

## How it works

It uses the [wireguard-go](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack) netstack package in combination with unprivileged network namespaces.

The majority of this code is based on the [httptap](https://github.com/monasticacademy/httptap) code, used under the terms of the MIT license.

## Caveats

- You need access to `/dev/net/tun`
- ICMP echo is temporarily not supported
