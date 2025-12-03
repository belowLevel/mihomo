package proxydialer

import (
	"context"
	"net"
	"net/netip"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type proxyDialer struct {
	proxy     C.ProxyAdapter
	statistic bool
}

func New(proxy C.ProxyAdapter, statistic bool) C.Dialer {
	return proxyDialer{proxy: proxy, statistic: statistic}
}

func (p proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	currentMeta := &C.Metadata{Type: C.INNER}
	if err := currentMeta.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	if strings.Contains(network, "udp") { // using in wireguard outbound
		pc, err := p.listenPacket(ctx, currentMeta)
		if err != nil {
			return nil, err
		}
		if !currentMeta.Resolved() { // should not happen, maybe by a wrongly implemented proxy, but we can handle this (:
			err = pc.ResolveUDP(ctx, currentMeta)
			if err != nil {
				return nil, err
			}
		}
		return N.NewBindPacketConn(pc, currentMeta.UDPAddr()), nil
	}
	conn, err := p.proxy.DialContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		channel := p.proxy.Name()
		manager, ok := statistic.ChannelManager[channel]
		if !ok {
			statistic.ChannelMutex.Lock()
			manager, ok = statistic.ChannelManager[channel]
			if !ok {
				manager = statistic.NewManager(channel)
			}
			statistic.ChannelMutex.Unlock()
		}
		conn = statistic.NewTCPTracker(conn, manager, currentMeta, nil, 0, 0, false)
	}
	return conn, err
}

func (p proxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	currentMeta := &C.Metadata{Type: C.INNER, DstIP: rAddrPort.Addr(), DstPort: rAddrPort.Port()}
	return p.listenPacket(ctx, currentMeta)
}

func (p proxyDialer) listenPacket(ctx context.Context, currentMeta *C.Metadata) (C.PacketConn, error) {
	currentMeta.NetWork = C.UDP
	pc, err := p.proxy.ListenPacketContext(ctx, currentMeta)
	if err != nil {
		return nil, err
	}
	if p.statistic {
		channel := p.proxy.Name()
		manager, ok := statistic.ChannelManager[channel]
		if !ok {
			statistic.ChannelMutex.Lock()
			manager, ok = statistic.ChannelManager[channel]
			if !ok {
				manager = statistic.NewManager(channel)
			}
			statistic.ChannelMutex.Unlock()
		}
		pc = statistic.NewUDPTracker(pc, manager, currentMeta, nil, 0, 0, false)
	}
	return pc, nil
}
