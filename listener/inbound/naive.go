package inbound

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/naive"
	"github.com/metacubex/mihomo/log"
	"net"
)

type NaiveOption struct {
	BaseOption
	naive.Config
}

func (o NaiveOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type NaiveTunnel struct {
	*Base
	config *NaiveOption
	l      net.Listener
}

func NewNaiveTunnel(options *NaiveOption) (*NaiveTunnel, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &NaiveTunnel{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (v *NaiveTunnel) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *NaiveTunnel) Address() string {
	return v.RawAddress()
}

// Listen implements constant.InboundListener
func (v *NaiveTunnel) Listen(tunnel C.Tunnel) error {
	l, err := naive.New(v.Address(), &v.config.Config, tunnel)
	if err != nil {
		return err
	}
	v.l = l
	log.Infoln("Naive[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *NaiveTunnel) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*NaiveTunnel)(nil)
