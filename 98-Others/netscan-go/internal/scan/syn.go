package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"iter"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/time/rate"

	"netscan/internal/model"
)

// SYNProber discovers open ports with a stateless SYN scan (masscan-style): it
// sends bare SYNs from a raw L3 socket, encodes a validation cookie in the TCP
// sequence number, and captures SYN-ACK replies with pcap — keeping no kernel
// connection state per target.
//
// Requires CAP_NET_RAW (setcap or root). The kernel, seeing a SYN-ACK for a
// connection it has no socket for, will emit a RST to the target; capture still
// works (pcap already saw the reply), but to avoid sending those stray RSTs run
// with an iptables rule dropping outbound RSTs from the scan source port.
//
// v1 buffers responding hosts and emits them after a grace period rather than
// streaming — the responding set is a tiny fraction of the address space.
type SYNProber struct {
	Ports   []uint16
	Retries int
	Grace   time.Duration
	Limiter *rate.Limiter // optional throttle

	secret  uint32
	srcPort uint16
}

// NewSYNProber builds a SYN prober with a random cookie secret. srcPort is the
// TCP source port for the scan (0 picks a random ephemeral port); pinning it
// lets an iptables RST rule be scoped to exactly this scan.
func NewSYNProber(ports []uint16, retries int, grace time.Duration, srcPort uint16, limiter *rate.Limiter) *SYNProber {
	if retries < 1 {
		retries = 1
	}
	if srcPort == 0 {
		srcPort = uint16(40000 + rand.IntN(20000))
	}
	return &SYNProber{
		Ports:   ports,
		Retries: retries,
		Grace:   grace,
		Limiter: limiter,
		secret:  rand.Uint32(),
		srcPort: srcPort,
	}
}

// SrcPort reports the TCP source port used for the scan (useful for scoping an
// iptables RST rule).
func (p *SYNProber) SrcPort() uint16 { return p.srcPort }

func (p *SYNProber) Run(ctx context.Context, addrs iter.Seq[netip.Addr], out chan<- model.WireRecord) error {
	iface, srcIP, err := defaultRoute()
	if err != nil {
		return fmt.Errorf("route discovery: %w", err)
	}

	// A short read timeout (not BlockForever) lets the receiver poll a stop flag
	// and exit cleanly — closing a pcap handle blocked in a read is unsafe.
	handle, err := pcap.OpenLive(iface, 65536, false, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w (need CAP_NET_RAW?)", iface, err)
	}
	// Only our SYN-ACK replies: destined to our scan source port, SYN+ACK set.
	filter := fmt.Sprintf("tcp and dst port %d and (tcp[13] & 0x12) = 0x12", p.srcPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("bpf filter: %w", err)
	}

	var (
		mu      sync.Mutex
		openMap = map[netip.Addr]map[uint16]struct{}{}
		stop    atomic.Bool
	)
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		linkType := handle.LinkType()
		for !stop.Load() {
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if err != nil {
				return
			}
			packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			tl := packet.Layer(layers.LayerTypeTCP)
			nl := packet.Layer(layers.LayerTypeIPv4)
			if tl == nil || nl == nil {
				continue
			}
			tcp := tl.(*layers.TCP)
			ip := nl.(*layers.IPv4)
			if !tcp.SYN || !tcp.ACK {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip.SrcIP.To4())
			if !ok {
				continue
			}
			if tcp.Ack != p.cookie(addr, uint16(tcp.SrcPort))+1 {
				continue // not a reply to one of our SYNs
			}
			mu.Lock()
			if openMap[addr] == nil {
				openMap[addr] = map[uint16]struct{}{}
			}
			openMap[addr][uint16(tcp.SrcPort)] = struct{}{}
			mu.Unlock()
		}
	}()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		stop.Store(true)
		<-recvDone
		handle.Close()
		return fmt.Errorf("raw socket: %w (need CAP_NET_RAW?)", err)
	}

	src4 := srcIP.As4()
	// send returns only on context cancellation or limiter error; either way we
	// still drain replies already in flight, so the result is ignored here.
	_ = p.send(ctx, fd, src4, addrs)
	syscall.Close(fd)

	// Wait for late replies, then stop the receiver and close the handle.
	select {
	case <-time.After(p.Grace):
	case <-ctx.Done():
	}
	stop.Store(true)
	<-recvDone
	handle.Close()

	mu.Lock()
	defer mu.Unlock()
	for addr, ports := range openMap {
		list := make([]uint16, 0, len(ports))
		for pt := range ports {
			list = append(list, pt)
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		select {
		case out <- model.WireRecord{IP: addr, OpenPorts: list, DiscoveredAt: time.Now().UTC()}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func (p *SYNProber) send(ctx context.Context, fd int, src4 [4]byte, addrs iter.Seq[netip.Addr]) error {
	for addr := range addrs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dst4 := addr.As4()
		for _, port := range p.Ports {
			pkt, err := p.craft(src4, dst4, port)
			if err != nil {
				continue
			}
			for r := 0; r < p.Retries; r++ {
				if p.Limiter != nil {
					if err := p.Limiter.Wait(ctx); err != nil {
						return err
					}
				}
				_ = syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst4})
			}
		}
	}
	return nil
}

func (p *SYNProber) craft(src, dst [4]byte, port uint16) ([]byte, error) {
	seq := p.cookie(netip.AddrFrom4(dst), port)
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP(src[:]),
		DstIP:    net.IP(dst[:]),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(p.srcPort),
		DstPort: layers.TCPPort(port),
		Seq:     seq,
		SYN:     true,
		Window:  1024,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cookie derives the SYN sequence number from the target and a per-run secret,
// so a SYN-ACK can be validated (ack == cookie+1) without per-target state.
func (p *SYNProber) cookie(ip netip.Addr, port uint16) uint32 {
	b := ip.As4()
	x := binary.BigEndian.Uint32(b[:]) ^ (uint32(port) << 16) ^ p.secret
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16
	return x
}

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
