package scan

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// Shared raw-socket + capture scaffolding for the privileged probers (SYN, ICMP).
// Both craft full IPv4 packets on a raw L3 socket and read replies via pcap, so
// the route discovery, send socket, and capture handle are factored out here.

// defaultRoute finds the outbound interface name and source IPv4 address the
// kernel would use to reach the internet.
func defaultRoute() (string, netip.Addr, error) {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", netip.Addr{}, err
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", netip.Addr{}, fmt.Errorf("unexpected local address type")
	}
	src, ok := netip.AddrFromSlice(la.IP.To4())
	if !ok {
		return "", netip.Addr{}, fmt.Errorf("no IPv4 source address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}, err
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if na, ok := netip.AddrFromSlice(ipnet.IP.To4()); ok && na == src {
				return ifc.Name, src, nil
			}
		}
	}
	return "", netip.Addr{}, fmt.Errorf("cannot find interface for source %s", src)
}

// openSendSocket opens a raw IPv4 socket for sending hand-crafted L3 packets
// (IPPROTO_RAW: the kernel does not add an IP header). Requires CAP_NET_RAW.
func openSendSocket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
}

// openCapture opens a pcap live handle on iface with the given BPF filter and a
// short read timeout (so a receiver can poll a stop flag and exit cleanly rather
// than block forever in a read). Requires CAP_NET_RAW.
func openCapture(iface, filter string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 65536, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w (need CAP_NET_RAW?)", iface, err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("bpf filter: %w", err)
	}
	return handle, nil
}
