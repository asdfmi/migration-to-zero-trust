package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"migration-to-zero-trust/wg-server/internal/controlplane"

	"github.com/florianl/go-nflog/v2"
)

const (
	defaultQueueSize = 1024
	pushInterval     = 10 * time.Second
	maxBatchSize     = 100
)

type peerNet struct {
	net  *net.IPNet
	id   string
	name string
}

type Logger struct {
	nf      *nflog.Nflog
	events  chan controlplane.LogEntry
	peers   []peerNet
	cp      *controlplane.Client
	dropped uint64
}

func NewLogger(loggingGroup int, cp *controlplane.Client) (*Logger, error) {
	nf, err := nflog.Open(&nflog.Config{
		Group:    uint16(loggingGroup),
		Copymode: nflog.CopyPacket,
	})
	if err != nil {
		return nil, fmt.Errorf("nflog open: %w", err)
	}

	return &Logger{
		nf:     nf,
		events: make(chan controlplane.LogEntry, defaultQueueSize),
		cp:     cp,
	}, nil
}

func (l *Logger) UpdatePeers(policies []controlplane.Policy) {
	peers := make([]peerNet, 0)
	for _, policy := range policies {
		for _, cidr := range policy.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			peers = append(peers, peerNet{net: ipNet, id: policy.ClientID, name: policy.ClientName})
		}
	}
	l.peers = peers
}

func (l *Logger) Close() error {
	if l == nil || l.nf == nil {
		return nil
	}
	return l.nf.Close()
}

func (l *Logger) Run(ctx context.Context) error {
	if l == nil {
		return nil
	}

	go l.startPusher(ctx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.nf.Register(ctx, l.handle)
	}()

	for {
		select {
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("nflog register: %w", err)
			}
			errCh = nil
		case <-ctx.Done():
			return nil
		}
	}
}

func (l *Logger) startPusher(ctx context.Context) {
	ticker := time.NewTicker(pushInterval)
	defer ticker.Stop()

	batch := make([]controlplane.LogEntry, 0, maxBatchSize)

	for {
		select {
		case ev := <-l.events:
			batch = append(batch, ev)
			if len(batch) >= maxBatchSize {
				l.pushBatch(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				l.pushBatch(ctx, batch)
				batch = batch[:0]
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				l.pushBatch(context.Background(), batch)
			}
			return
		}
	}
}

func (l *Logger) pushBatch(ctx context.Context, batch []controlplane.LogEntry) {
	if err := l.cp.PushLogs(ctx, batch); err != nil {
		log.Printf("push logs error: %v", err)
	}
}

func (l *Logger) handle(attrs nflog.Attribute) int {
	if attrs.Payload == nil || len(*attrs.Payload) == 0 {
		return 0
	}

	payload := *attrs.Payload

	ev := controlplane.LogEntry{
		Timestamp: time.Now(),
		Length:    len(payload),
	}

	if attrs.Timestamp != nil {
		ev.Timestamp = *attrs.Timestamp
	}

	if pkt, ok := parsePacket(payload); ok {
		ev.SrcIP = pkt.srcIP
		ev.DstIP = pkt.dstIP
		ev.SrcPort = pkt.srcPort
		ev.DstPort = pkt.dstPort
		ev.Proto = pkt.proto
		if pkt.srcIP != "" {
			ev.ClientID, ev.ClientName = l.matchClient(net.ParseIP(pkt.srcIP))
		}
	}

	select {
	case l.events <- ev:
	default:
		atomic.AddUint64(&l.dropped, 1)
	}

	return 0
}

func (l *Logger) matchClient(ip net.IP) (string, string) {
	if ip == nil {
		return "", ""
	}
	for _, peer := range l.peers {
		if peer.net.Contains(ip) {
			return peer.id, peer.name
		}
	}
	return "", ""
}

type parsedPacket struct {
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
	proto   string
}

func parsePacket(payload []byte) (parsedPacket, bool) {
	if len(payload) < 1 {
		return parsedPacket{}, false
	}

	version := payload[0] >> 4
	switch version {
	case 4:
		return parseIPv4(payload)
	case 6:
		return parseIPv6(payload)
	default:
		return parsedPacket{}, false
	}
}

func parseIPv4(payload []byte) (parsedPacket, bool) {
	if len(payload) < 20 {
		return parsedPacket{}, false
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return parsedPacket{}, false
	}

	proto := payload[9]
	src := net.IPv4(payload[12], payload[13], payload[14], payload[15]).String()
	dst := net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()

	srcPort, dstPort := parsePorts(payload[ihl:], proto)

	return parsedPacket{
		srcIP:   src,
		dstIP:   dst,
		srcPort: srcPort,
		dstPort: dstPort,
		proto:   protoName(proto),
	}, true
}

func parseIPv6(payload []byte) (parsedPacket, bool) {
	if len(payload) < 40 {
		return parsedPacket{}, false
	}

	proto := payload[6]
	src := net.IP(payload[8:24]).String()
	dst := net.IP(payload[24:40]).String()

	srcPort, dstPort := parsePorts(payload[40:], proto)

	return parsedPacket{
		srcIP:   src,
		dstIP:   dst,
		srcPort: srcPort,
		dstPort: dstPort,
		proto:   protoName(proto),
	}, true
}

func parsePorts(payload []byte, proto byte) (int, int) {
	if (proto == 6 || proto == 17) && len(payload) >= 4 {
		src := int(binary.BigEndian.Uint16(payload[0:2]))
		dst := int(binary.BigEndian.Uint16(payload[2:4]))
		return src, dst
	}
	return 0, 0
}

func protoName(proto byte) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto_%d", proto)
	}
}
