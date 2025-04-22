# wgcage

Force any application to route through a wireguard VPN with no chance of leaks.

No root required (assuming unprivileged user namespaces are enabled).

## Quickstart

You can run any command and force it to route through wireguard.

Let's start with curl:

```shell
wgcage \
  --server <wireguard-server-ip> \
  --public-key <server-public-key> \
  --private-key-file /path/to/client/wg/privage/key \
  curl https://api.myip.com

{"ip": "<wireguard server ip>"}
```

You can also open a shell and look around:

```shell
wgcage \
  --server <wireguard-server-ip> \
  --public-key <server-public-key> \
  --private-key-file /path/to/client/wg/privage/key \
  bash

# ip addr

1: lo: <LOOPBACK,UP,LOWER_UP>

2: wgcage0: <BROADCAST,UP> mtu 1420 ....
```

## Ubuntu 23.10 and later

On Ubuntu 23.10 and later you will need to run the following in order to use wgcage:

```shell
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

What this does is disable a [recent kernel feature that restricts unpriveleged user namespaces](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces).

## How it works

TODO

## Caveats

- You need access to `/dev/net/tun`
- ICMP echo is temporarily not supported
