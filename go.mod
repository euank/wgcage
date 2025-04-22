module github.com/euank/wgcage

go 1.23.1

require (
	github.com/alexflint/go-arg v1.5.1
	github.com/ebitengine/purego v0.8.1
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.3.0
	golang.org/x/sys v0.32.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	gvisor.dev/gvisor v0.0.0-20250421234849-d561420079a1
)

require (
	github.com/alexflint/go-scalar v1.2.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard => github.com/euank/wireguard-go v0.0.0-20250422172644-9fd912b95c73
