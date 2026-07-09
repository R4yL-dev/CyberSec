package scan

import (
	"context"
	"encoding/binary"
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

// ICMPProber is a stateless ICMP-echo liveness sweep, mirroring SYNProber: it
// sends echo requests from a raw L3 socket, encodes a validation cookie in the
// ICMP sequence number, and captures echo replies with pcap — no per-target
// kernel state. It complements the SYN sweep in the adaptive scan's pass 1,
// catching hosts that answer ping but no common TCP port.
//
// Requires CAP_NET_RAW (setcap or root). Responders are streamed as
// WireRecords with NO open ports — a liveness signal for live-block selection,
// not an enrichable host (ns-ingest refreshes the row but queues no work).
type ICMPProber struct {
	Retries  int
	Grace    time.Duration
	Limiter  *rate.Limiter // optional throttle
	Progress *int64        // optional: incremented once per echo sent

	secret uint32
	id     uint16 // ICMP identifier scoping our probes (like SYN's source port)
}

// NewICMPProber builds an ICMP echo prober with a random cookie secret and id.
func NewICMPProber(retries int, grace time.Duration, limiter *rate.Limiter) *ICMPProber {
	if retries < 1 {
		retries = 1
	}
	return &ICMPProber{
		Retries: retries,
		Grace:   grace,
		Limiter: limiter,
		secret:  rand.Uint32(),
		id:      uint16(1 + rand.IntN(65535)),
	}
}

func (p *ICMPProber) Run(ctx context.Context, addrs iter.Seq[netip.Addr], out chan<- model.WireRecord) error {
	iface, srcIP, err := defaultRoute()
	if err != nil {
		return err
	}
	handle, err := openCapture(iface, "icmp[icmptype] = icmp-echoreply")
	if err != nil {
		return err
	}

	// seen deduplicates responders (one record per host). The receiver is the
	// sole accessor, so no lock is needed.
	seen := map[netip.Addr]struct{}{}
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
			nl := packet.Layer(layers.LayerTypeIPv4)
			il := packet.Layer(layers.LayerTypeICMPv4)
			if nl == nil || il == nil {
				continue
			}
			ip := nl.(*layers.IPv4)
			icmp := il.(*layers.ICMPv4)
			if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip.SrcIP.To4())
			if !ok {
				continue
			}
			// An echo reply echoes back our id + seq: validate both so stray ICMP
			// isn't counted as a responder.
			if icmp.Id != p.id || icmp.Seq != p.cookie(addr) {
				continue
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			select {
			case out <- model.WireRecord{IP: addr, OpenPorts: nil, DiscoveredAt: time.Now().UTC()}:
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
		return err
	}

	src4 := srcIP.As4()
	_ = p.send(ctx, fd, src4, addrs)
	syscall.Close(fd)

	select {
	case <-time.After(p.Grace):
	case <-ctx.Done():
	}
	stop.Store(true)
	<-recvDone
	handle.Close()
	return ctx.Err()
}

// send transmits one echo request per address, repeated as `Retries` full passes
// over the target sequence (spacing retransmits, robust against burst loss). It
// re-ranges addrs each pass, which requires the sequence to be restartable.
func (p *ICMPProber) send(ctx context.Context, fd int, src4 [4]byte, addrs iter.Seq[netip.Addr]) error {
	for pass := 0; pass < p.Retries; pass++ {
		for addr := range addrs {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			dst4 := addr.As4()
			pkt, err := p.craft(src4, dst4)
			if err != nil {
				continue
			}
			if p.Limiter != nil {
				if err := p.Limiter.Wait(ctx); err != nil {
					return err
				}
			}
			if p.Progress != nil {
				atomic.AddInt64(p.Progress, 1)
			}
			_ = syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst4})
		}
	}
	return nil
}

func (p *ICMPProber) craft(src, dst [4]byte) ([]byte, error) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IP(src[:]),
		DstIP:    net.IP(dst[:]),
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       p.id,
		Seq:      p.cookie(netip.AddrFrom4(dst)),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, icmp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cookie derives the ICMP sequence number from the target and a per-run secret,
// so an echo reply can be validated (seq == cookie) without per-target state.
func (p *ICMPProber) cookie(ip netip.Addr) uint16 {
	b := ip.As4()
	x := binary.BigEndian.Uint32(b[:]) ^ p.secret
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	return uint16(x)
}
