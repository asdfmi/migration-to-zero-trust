package logging

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"migration-to-zero-trust/wg-server/internal/config"

	"github.com/florianl/go-nflog"
	"github.com/google/nftables"
)

const (
	defaultQueueSize = 1024
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     string    `json:"src_ip,omitempty"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	DstPort   int       `json:"dst_port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
	Prefix    string    `json:"prefix,omitempty"`
	InIface   string    `json:"in_iface,omitempty"`
	OutIface  string    `json:"out_iface,omitempty"`
	Length    int       `json:"length"`
}

type peerNet struct {
	net *net.IPNet
	id  string
}

type Logger struct {
	nflog   *nflog.Nflog
	events  chan Event
	peers   []peerNet
	path    string
	dropped uint64
}

func Run(cfg config.Config) error {
	if !cfg.Logging.Enabled {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ensureNFLOGRule(&nftables.Conn{}, cfg.WG.Iface, uint16(cfg.Logging.Group)); err != nil {
		return err
	}

	logger, err := New(cfg)
	if err != nil {
		return err
	}
	defer logger.Close()

	return logger.run(ctx)
}

func New(cfg config.Config) (*Logger, error) {
	nf, err := nflog.Open(&nflog.Config{
		Group:    uint16(cfg.Logging.Group),
		Copymode: nflog.CopyPacket,
	})
	if err != nil {
		return nil, fmt.Errorf("nflog open: %w", err)
	}

	return &Logger{
		nflog:  nf,
		events: make(chan Event, defaultQueueSize),
		peers:  buildPeers(cfg),
		path:   cfg.Logging.Path,
	}, nil
}

func (l *Logger) Close() error {
	if l.nflog == nil {
		return nil
	}
	return l.nflog.Close()
}

func (l *Logger) run(ctx context.Context) error {
	if err := l.startWriter(ctx); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.nflog.Register(ctx, l.handle)
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

func (l *Logger) startWriter(ctx context.Context) error {
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}

	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("log open: %w", err)
	}

	writer := bufio.NewWriter(file)
	ticker := time.NewTicker(1 * time.Second)

	go func() {
		defer ticker.Stop()
		defer file.Close()
		defer writer.Flush()

		for {
			select {
			case ev := <-l.events:
				line, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				_, _ = writer.Write(line)
				_ = writer.WriteByte('\n')
			case <-ticker.C:
				_ = writer.Flush()
			case <-ctx.Done():
				_ = writer.Flush()
				return
			}
		}
	}()

	return nil
}

func (l *Logger) handle(attrs nflog.Attribute) int {
	if attrs.Payload == nil {
		return 0
	}

	ev := Event{
		Timestamp: time.Now(),
		Length:    len(attrs.Payload),
	}

	if attrs.Timestamp != nil {
		ev.Timestamp = *attrs.Timestamp
	}
	if attrs.Prefix != nil {
		ev.Prefix = *attrs.Prefix
	}
	if attrs.InDev != nil {
		ev.InIface = ifaceName(int(*attrs.InDev))
	}
	if attrs.OutDev != nil {
		ev.OutIface = ifaceName(int(*attrs.OutDev))
	}

	if pkt, ok := parsePacket(attrs.Payload); ok {
		ev.SrcIP = pkt.srcIP
		ev.DstIP = pkt.dstIP
		ev.SrcPort = pkt.srcPort
		ev.DstPort = pkt.dstPort
		ev.Proto = pkt.proto
		if pkt.srcIP != "" {
			ev.ClientID = matchClient(l.peers, net.ParseIP(pkt.srcIP))
		}
	}

	select {
	case l.events <- ev:
	default:
		atomic.AddUint64(&l.dropped, 1)
	}

	return 0
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

func ifaceName(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return iface.Name
}

func buildPeers(cfg config.Config) []peerNet {
	peers := make([]peerNet, 0)
	for _, peer := range cfg.WG.Peers {
		for _, cidr := range peer.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			peers = append(peers, peerNet{net: ipNet, id: peer.PublicKey})
		}
	}
	return peers
}

func matchClient(peers []peerNet, ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, peer := range peers {
		if peer.net.Contains(ip) {
			return peer.id
		}
	}
	return ""
}
