package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"migration-to-zero-trust/enforcer/internal/controlplane"

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

type resourceNet struct {
	net  *net.IPNet
	id   string
	name string
}

type parsedPacket struct {
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
	proto   string
}

type Logger struct {
	nf          *nflog.Nflog
	events      chan controlplane.LogEntry
	peersMu     sync.RWMutex
	peers       []peerNet
	resourcesMu sync.RWMutex
	resources   []resourceNet
	cp          *controlplane.Client
	dropped     uint64
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

func (l *Logger) UpdateLookupTables(policies []controlplane.Policy) {
	peers := make([]peerNet, 0)
	resourceMap := make(map[string]resourceNet) // deduplicate by CIDR
	for _, policy := range policies {
		for _, cidr := range policy.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			peers = append(peers, peerNet{net: ipNet, id: policy.ClientID, name: policy.ClientName})
		}
		for _, target := range policy.AllowedCIDRs {
			if _, exists := resourceMap[target.CIDR]; exists {
				continue
			}
			_, ipNet, err := net.ParseCIDR(target.CIDR)
			if err != nil {
				continue
			}
			resourceMap[target.CIDR] = resourceNet{net: ipNet, id: target.ResourceID, name: target.ResourceName}
		}
	}
	resources := make([]resourceNet, 0, len(resourceMap))
	for _, r := range resourceMap {
		resources = append(resources, r)
	}

	l.peersMu.Lock()
	l.peers = peers
	l.peersMu.Unlock()

	l.resourcesMu.Lock()
	l.resources = resources
	l.resourcesMu.Unlock()
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
	go l.startReceiver(ctx)
	<-ctx.Done()
	return nil
}

func (l *Logger) startReceiver(ctx context.Context) {
	handle := func(attrs nflog.Attribute) int {
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

		pkt, ok := parseIPv4Packet(payload)
		if !ok {
			return 0 // skip non-IPv4 packets
		}
		ev.SrcIP = pkt.srcIP
		ev.DstIP = pkt.dstIP
		ev.SrcPort = pkt.srcPort
		ev.DstPort = pkt.dstPort
		ev.Proto = pkt.proto
		ev.ClientID, ev.ClientName = l.matchClient(net.ParseIP(pkt.srcIP))
		ev.ResourceID, ev.ResourceName = l.matchResource(net.ParseIP(pkt.dstIP))

		select {
		case l.events <- ev:
		default:
			atomic.AddUint64(&l.dropped, 1)
		}
		return 0
	}

	if err := l.nf.RegisterWithErrorFunc(ctx, handle, func(err error) int {
		log.Printf("nflog error: %v", err)
		return 0
	}); err != nil {
		log.Printf("nflog register: %v", err)
	}
}

func (l *Logger) startPusher(ctx context.Context) {
	ticker := time.NewTicker(pushInterval)
	defer ticker.Stop()

	push := func(c context.Context, batch []controlplane.LogEntry) {
		if err := l.cp.PushLogs(c, batch); err != nil {
			log.Printf("push logs error: %v", err)
		}
	}

	batch := make([]controlplane.LogEntry, 0, maxBatchSize)
	for {
		select {
		case ev := <-l.events:
			batch = append(batch, ev)
			if len(batch) >= maxBatchSize {
				push(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				push(ctx, batch)
				batch = batch[:0]
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				push(context.Background(), batch)
			}
			return
		}
	}
}

func (l *Logger) matchClient(ip net.IP) (string, string) {
	if ip == nil {
		return "", ""
	}
	l.peersMu.RLock()
	defer l.peersMu.RUnlock()
	for _, peer := range l.peers {
		if peer.net.Contains(ip) {
			return peer.id, peer.name
		}
	}
	return "", ""
}

func (l *Logger) matchResource(ip net.IP) (string, string) {
	if ip == nil {
		return "", ""
	}
	l.resourcesMu.RLock()
	defer l.resourcesMu.RUnlock()
	for _, res := range l.resources {
		if res.net.Contains(ip) {
			return res.id, res.name
		}
	}
	return "", ""
}

func parseIPv4Packet(payload []byte) (parsedPacket, bool) {
	if len(payload) < 20 {
		return parsedPacket{}, false
	}
	if payload[0]>>4 != 4 {
		return parsedPacket{}, false
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return parsedPacket{}, false
	}

	proto := payload[9]
	src := net.IPv4(payload[12], payload[13], payload[14], payload[15]).String()
	dst := net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()

	var srcPort, dstPort int
	if (proto == 6 || proto == 17) && len(payload) >= ihl+4 {
		srcPort = int(binary.BigEndian.Uint16(payload[ihl : ihl+2]))
		dstPort = int(binary.BigEndian.Uint16(payload[ihl+2 : ihl+4]))
	}

	return parsedPacket{
		srcIP:   src,
		dstIP:   dst,
		srcPort: srcPort,
		dstPort: dstPort,
		proto:   protoName(proto),
	}, true
}

func protoName(proto byte) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return fmt.Sprintf("proto_%d", proto)
	}
}
