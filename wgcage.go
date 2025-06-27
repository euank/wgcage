package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/euank/wirecage/pkg/overlay"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	dumpPacketsToSubprocess   = false
	dumpPacketsFromSubprocess = false
	ttl                       = 10
)

func run(ctx context.Context) error {
	var args struct {
		Tun       string `default:"wirecage" help:"name of the TUN device that will be created"`
		Subnet    string `default:"10.1.2.100/24" help:"IP address of the network interface that the subprocess will see"`
		Gateway   string `default:"10.1.2.1" help:"IP address of the gateway that intercepts and proxies network packets"`
		UID       int
		GID       int
		User      string `help:"run command as this user (username or id)"`
		NoOverlay bool   `arg:"--no-overlay,env:HTTPTAP_NO_OVERLAY" help:"do not mount any overlay filesystems"`
		Stack     string `arg:"env:HTTPTAP_STACK" default:"gvisor" help:"which tcp implementation to use: 'gvisor' or 'homegrown'"`
		LogLevel  string `arg:"--log-level" default:"info" help:"log level (debug, info, warn, error)"`

		WgPubKey      string `arg:"--wg-public-key" help:"wireguard server public key"`
		WgPrivKeyFile string `arg:"--wg-private-key-file" help:"wireguard private key file"`
		WgEndpoint    string `arg:"--wg-endpoint" help:"wireguard server endpoint"`
		WgIP          string `arg:"--wg-address" help:"our wireguard address (i.e. the 'allowed_ips' the server has for this peer)"`

		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	var logLevel slog.Level
	switch strings.ToLower(args.LogLevel) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q, must be one of: debug, info, warn, error", args.LogLevel)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	// first we re-exec ourselves in a new user namespace
	if !strings.HasPrefix(os.Args[0], "httptap.stage.") {
		slog.Debug(fmt.Sprintf("at first stage, launching second stage in a new user namespace..."))

		// Decide which user and group we should later switch to. We must do this before creating the user
		// namespace because then we will not know which user we were originally launched by.
		uid := os.Geteuid()
		gid := os.Getegid()
		if args.User != "" {
			u, err := user.Lookup(args.User)
			if err != nil {
				return fmt.Errorf("error looking up user %q: %w", args.User, err)
			}

			uid, err = strconv.Atoi(u.Uid)
			if err != nil {
				return fmt.Errorf("error parsing user id %q as a number: %w", u.Uid, err)
			}

			gid, err = strconv.Atoi(u.Gid)
			if err != nil {
				return fmt.Errorf("error parsing group id %q as a number: %w", u.Gid, err)
			}
		}

		// Here we move to a new user namespace, which is an unpriveleged operation, and which
		// allows us to do everything else without being root.
		//
		// In a C program, we could run unshare(CLONE_NEWUSER) and directly be in a new user
		// namespace. In a Go program that is not possible because all Go programs are multithreaded
		// (even with GOMAXPROCS=1), and unshare(CLONE_NEWUSER) is only available to single-threaded
		// programs.
		//
		// Our best option is to launch ourselves in a subprocess that is in a new user namespace,
		// using /proc/self/exe, which contains the executable code for the current process. This
		// is the same approach taken by docker's reexec package.

		cmd := exec.Command("/proc/self/exe")
		cmd.Args = append([]string{
			"httptap.stage.2",
			"--uid", strconv.Itoa(uid),
			"--gid", strconv.Itoa(gid),
		},
			os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			}},
			GidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			}},
		}
		err := cmd.Run()
		// if the subprocess exited with an error code then do not print any
		// extra information but do exit with the same code
		if err != nil {
			return fmt.Errorf("error re-executing ourselves in a new user namespace: %w", err)
		}
		return nil
	}

	if os.Args[0] == "httptap.stage.3" {
		slog.Debug("at third stage...")

		// there are three (!) user/group IDs for a process: the real, effective, and saved
		// they have the purpose of allowing the process to go "back" to them
		// here we set just the effective, which, when you are root, sets all three

		if args.GID != 0 {
			slog.Debug(fmt.Sprintf("switching to gid %d", args.GID))
			err := unix.Setgid(args.GID)
			if err != nil {
				return fmt.Errorf("error switching to group %v: %w", args.GID, err)
			}
		}

		if args.UID != 0 {
			slog.Debug(fmt.Sprintf("switching to uid %d", args.UID))
			err := unix.Setuid(args.UID)
			if err != nil {
				return fmt.Errorf("error switching to user %v: %w", args.UID, err)
			}
		}

		slog.Debug(fmt.Sprintf("third stage now in uid %d, gid %d, launching final subprocess...", unix.Getuid(), unix.Getgid()))

		// launch the command that the user originally requested
		cmd := exec.Command(args.Command[0])
		cmd.Args = args.Command
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error launching final subprocess from third stage: %w", err)
		}
		return nil
	}

	slog.Debug("at second stage")

	if args.WgEndpoint == "" {
		return fmt.Errorf("--wg-endpoint is required")
	}
	if args.WgPubKey == "" {
		return fmt.Errorf("--wg-public-key is required")
	}
	if args.WgPrivKeyFile == "" {
		return fmt.Errorf("--wg-private-key-file is required")
	}
	if args.WgPrivKeyFile == "" {
		return fmt.Errorf("--wg-private-key-file is required")
	}

	privKey, err := os.ReadFile(args.WgPrivKeyFile)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", args.WgPrivKeyFile, err)
	}
	// create wireguard tun
	proxy, err := newWgProxy(ctx, args.WgIP, string(privKey), args.WgPubKey, args.WgEndpoint)
	if err != nil {
		return fmt.Errorf("could not make wg prox: %w", err)
	}

	// lock the OS thread because network and mount namespaces are specific to a single OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// create a new network namespace
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("error creating network namespace: %w", err)
	}

	// create a tun device in the new namespace
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: args.Tun,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating tun device: %w", err)
	}

	// find the link for the device we just created
	link, err := netlink.LinkByName(args.Tun)
	if err != nil {
		return fmt.Errorf("error finding link for new tun device %q: %w", args.Tun, err)
	}

	slog.Debug(fmt.Sprintf("tun device has MTU %d", link.Attrs().MTU))

	// bring the link up
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error bringing up link for %q: %w", args.Tun, err)
	}

	// parse the subnet that we will assign to the interface within the namespace
	linksubnet, err := netlink.ParseIPNet(args.Subnet)
	if err != nil {
		return fmt.Errorf("error parsing subnet: %w", err)
	}

	// assign the address we just parsed to the link, which will change the routing table
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: linksubnet,
	})
	if err != nil {
		return fmt.Errorf("error assign address to tun device: %w", err)
	}

	// parse the subnet corresponding to all globally routable ipv4 addresses
	ip4Routable, err := netlink.ParseIPNet("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("error parsing global subnet: %w", err)
	}

	// parse the subnet corresponding to all globally routable ipv6 addresses
	ip6Routable, err := netlink.ParseIPNet("2000::/3")
	if err != nil {
		return fmt.Errorf("error parsing global subnet: %w", err)
	}

	// add a route that sends all ipv4 traffic going anywhere to the tun device
	err = netlink.RouteAdd(&netlink.Route{
		Dst:       ip4Routable,
		LinkIndex: link.Attrs().Index,
	})
	if err != nil {
		return fmt.Errorf("error creating default ipv4 route: %w", err)
	}

	// add a route that sends all ipv6 traffic going anywhere to the tun device
	err = netlink.RouteAdd(&netlink.Route{
		Dst:       ip6Routable,
		LinkIndex: link.Attrs().Index,
	})
	if err != nil {
		slog.Debug(fmt.Sprintf("error creating default ipv6 route: %v, ignoring", err))
	}

	// find the loopback device
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("error finding link for loopback device: %w", err)
	}

	// bring the link up
	err = netlink.LinkSetUp(loopback)
	if err != nil {
		return fmt.Errorf("error bringing up link for loopback device: %w", err)
	}

	// if --dump was provided then start watching everything
	// if args.DumpTCP {
	//	iface, err := net.InterfaceByName(args.Tun)
	//	if err != nil {
	//		return err
	//	}

	//	// packet.Raw means listen for raw IP packets (requires root permissions)
	//	// unix.ETH_P_ALL means listen for all packets
	//	conn, err := packet.Listen(iface, packet.Raw, unix.ETH_P_ALL, nil)
	//	if err != nil {
	//		if errors.Is(err, unix.EPERM) {
	//			return fmt.Errorf("you need root permissions to read raw packets (%w)", err)
	//		}
	//		return fmt.Errorf("error listening for raw packet: %w", err)
	//	}

	//	// set promiscuous mode so that we see everything
	//	err = conn.SetPromiscuous(true)
	//	if err != nil {
	//		return fmt.Errorf("error setting raw packet connection to promiscuous mode: %w", err)
	//	}

	//	go func() {
	//		// read packets forever
	//		buf := make([]byte, iface.MTU)
	//		for {
	//			n, _, err := conn.ReadFrom(buf)
	//			if err != nil {
	//				log.Printf("error reading raw packet: %v, aborting dump", err)
	//				return
	//			}

	//			// decode and dump
	//			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
	//			log.Println(packet.Dump())
	//		}
	//	}()
	//}

	// if /etc/ is a directory then set up an overlay
	if st, err := os.Lstat("/etc"); err == nil && st.IsDir() && !args.NoOverlay {
		slog.Debug("overlaying /etc ...")

		// overlay resolv.conf
		mount, err := overlay.Mount("/etc", overlay.File("resolv.conf", []byte("nameserver "+args.Gateway+"\n")))
		if err != nil {
			return fmt.Errorf("error setting up overlay: %w", err)
		}
		defer mount.Remove()
	}

	// set up environment variables for the subprocess
	env := append(
		os.Environ(),
		"PS1=wirecage # ",
		"wirecage=1",
	)

	slog.Debug("running subcommand now ================")

	// start sending packets to the process
	toSubprocess := make(chan []byte, 1000)
	go copyToDevice(ctx, tun, toSubprocess)

	slog.Debug(fmt.Sprintf("listening on %v", args.Tun))

	// create the stack with udp and tcp protocols
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	// create a link endpoint based on the TUN device
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs: []int{int(tun.ReadWriteCloser.(*os.File).Fd())},
		MTU: uint32(link.Attrs().MTU),
	})
	if err != nil {
		return fmt.Errorf("error creating link from tun device file descriptor: %v", err)
	}

	// create the TCP forwarder, which accepts gvisor connections and notifies the mux
	const maxInFlight = 100 // maximum simultaneous connections
	tcpForwarder := tcp.NewForwarder(s, 0, maxInFlight, func(r *tcp.ForwarderRequest) {
		// remote address is the IP address of the subprocess
		// local address is IP address that the subprocess was trying to reach
		slog.Debug("at TCP forwarder",
			"from", fmt.Sprintf("%v:%v", r.ID().RemoteAddress.String(), r.ID().RemotePort),
			"to", fmt.Sprintf("%v:%v", r.ID().LocalAddress.String(), r.ID().LocalPort),
		)
		go func() {
			req := &tcpRequest{r, new(waiter.Queue)}
			conn, err := req.Accept()
			if err != nil {
				slog.Error("error accepting tcp", "err", err)
				r.Complete(true)
				return
			}
			dst := conn.LocalAddr().String()
			proxy.ProxyConn("tcp", dst, conn)
		}()
	})

	// TODO: this UDP forwarder sometimes only ever processes one UDP packet, other times it keeps going... :/
	// create the UDP forwarder, which accepts UDP packets and notifies the mux
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		slog.Debug("at UDP forwarder",
			"from", fmt.Sprintf("%v:%v", r.ID().RemoteAddress.String(), r.ID().RemotePort),
			"to", fmt.Sprintf("%v:%v", r.ID().LocalAddress.String(), r.ID().LocalPort),
		)

		// create an endpoint for responding to this packet -- unlike TCP we do this right away because there is no SYN+ACK to decide whether to send
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			slog.Error("error creating udp endpoint", "err", err)
			return
		}

		// dispatch the request via the mux
		go func() {
			conn := gonet.NewUDPConn(&wq, ep)
			dst := conn.LocalAddr().String()
			proxy.ProxyConn("udp", dst, conn)
		}()
	})

	// register the forwarders with the stack
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, func(id stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		slog.Debug(fmt.Sprintf("got icmp packet %v => %v", id.RemoteAddress, id.LocalAddress))
		return false // this means the packet was handled and no error handler needs to be invoked
	})
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, func(id stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		slog.Debug(fmt.Sprintf("got icmp6 packet %v => %v", id.RemoteAddress, id.LocalAddress))
		return false // this means the packet was handled and no error handler needs to be invoked
	})

	// create the network interface -- tun2socks says this must happen *after* registering the TCP forwarder
	nic := s.NextNICID()
	er := s.CreateNIC(nic, endpoint)
	if er != nil {
		return fmt.Errorf("error creating NIC: %v", er)
	}

	// set promiscuous mode so that the forwarder receives packets not addressed to us
	er = s.SetPromiscuousMode(nic, true)
	if er != nil {
		return fmt.Errorf("error activating promiscuous mode: %v", er)
	}

	// set spoofing mode so that we can send packets from any address
	er = s.SetSpoofing(nic, true)
	if er != nil {
		return fmt.Errorf("error activating spoofing mode: %v", er)
	}

	// set up the route table so that we can send packets to the subprocess
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nic,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nic,
		},
	})

	slog.Debug(fmt.Sprintf("launching third stage targetting uid %d, gid %d...", args.UID, args.GID))

	// launch the third stage in a second user namespace, this time with mappings reversed
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = append([]string{
		"httptap.stage.3",
		"--uid", strconv.Itoa(args.UID),
		"--gid", strconv.Itoa(args.GID), "--",
	},
		args.Command...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: args.UID,
			HostID:      0,
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: args.GID,
			HostID:      0,
			Size:        1,
		}},
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting third stage subprocess: %w", err)
	}

	// wait for the subprocess to complete
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("error running subprocess: %w", err)
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := run(context.Background())
	if err != nil {
		// if we exit due to a subprocess returning with non-zero exit code then do not
		// print any extraneous output but do exit with the same code
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}

		// for any other kind of error, print the error and exit with code 1
		log.Fatal(err)
	}
}
