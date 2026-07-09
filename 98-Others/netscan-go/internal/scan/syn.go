package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"iter"
	"math/rand/v2"
	"net"
	"net/netip"
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
// Responding hosts are streamed as their SYN-ACKs arrive (one record per open
// port, deduplicated); the send continues for a grace period afterward to catch
// late replies. Streaming lets enrichment overlap discovery.
type SYNProber struct {
	Ports    []uint16
	Retries  int
	Grace    time.Duration
	Limiter  *rate.Limiter // optional throttle
	Progress *int64        // optional: incremented once per SYN sent (probe)

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

	// Only our SYN-ACK replies: destined to our scan source port, SYN+ACK set.
	filter := fmt.Sprintf("tcp and dst port %d and (tcp[13] & 0x12) = 0x12", p.srcPort)
	handle, err := openCapture(iface, filter)
	if err != nil {
		return err
	}

	// seen deduplicates (host, port) so a retransmitted SYN-ACK is emitted once.
	// The receiver is the sole accessor, so no lock is needed.
	seen := map[netip.Addr]map[uint16]struct{}{}
	var stop atomic.Bool
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
			port := uint16(tcp.SrcPort)
			if tcp.Ack != p.cookie(addr, port)+1 {
				continue // not a reply to one of our SYNs
			}
			if seen[addr] == nil {
				seen[addr] = map[uint16]struct{}{}
			}
			if _, dup := seen[addr][port]; dup {
				continue
			}
			seen[addr][port] = struct{}{}
			// Stream the host as soon as it answers (one record per open port;
			// ns-ingest unions ports). This lets enrichment overlap discovery.
			select {
			case out <- model.WireRecord{IP: addr, OpenPorts: []uint16{port}, DiscoveredAt: time.Now().UTC()}:
			case <-ctx.Done():
				return
			}
		}
	}()

	fd, err := openSendSocket()
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
	return ctx.Err()
}

// send transmits one SYN per (address, port), repeated as `Retries` full passes
// over the target sequence rather than back-to-back copies — spacing
// retransmits across the whole scan is far more robust against burst loss
// (masscan does the same). It re-ranges addrs each pass, which requires the
// sequence to be restartable; target.Space.Randomized replays the same order.
func (p *SYNProber) send(ctx context.Context, fd int, src4 [4]byte, addrs iter.Seq[netip.Addr]) error {
	for pass := 0; pass < p.Retries; pass++ {
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
				if p.Limiter != nil {
					if err := p.Limiter.Wait(ctx); err != nil {
						return err
					}
				}
				if p.Progress != nil {
					atomic.AddInt64(p.Progress, 1) // count probes (SYNs), so rate matches --rate
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
