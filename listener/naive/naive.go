package naive

import (
	"crypto/tls"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"time"
)

type Config struct {
	Users             []string `inbound:"users"`
	Certificate       string   `inbound:"certificate"`
	PrivateKey        string   `inbound:"private-key"`
	MustPadding       bool     `inbound:"must-padding"`
	CongestionControl string   `inbound:"congestion-control,omitempty"`
	MaxPacingRate     uint64   `inbound:"max-pacing-rate,omitempty"`
	Fallback          string   `inbound:"fallback"`
}
type NaiveListener struct {
	net.Listener
	maxPacingRate     uint64
	congestionControl string
	tlsConfig         *tls.Config
}

func (n *NaiveListener) Accept() (net.Conn, error) {
	conn, err := n.Listener.Accept()
	if n.maxPacingRate > 0 {
		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			if n.congestionControl == "" {
				err := common.SetMaxPacingRate(tcpConn, n.maxPacingRate)
				if err != nil {
					log.Errorln("%s", err.Error())
				}
			} else {
				err := common.SetCongestion(tcpConn, n.congestionControl, n.maxPacingRate)
				if err != nil {
					log.Errorln("%s", err.Error())
				}
			}
		}

	}
	tlsConn := tls.Server(conn, n.tlsConfig)
	return tlsConn, err
}

type handler struct {
	naiveHandler    *naiveHandler
	fallbackHandler *fallbackHandler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.naiveHandler.naiveServe(w, r)
	if err == nil {
		return
	}
	log.Debugln("%s", err.Error())

	h.fallbackHandler.httpServe(w, r)

}

func New(addr string, config *Config, tunnel C.Tunnel, additions ...inbound.Addition) (*NaiveListener, error) {

	cert, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	fallbackHandler, err := NewFallbackHandler(config.Fallback)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           &handler{naiveHandler: NewNaiveHandler(config.Users, config, tunnel, additions), fallbackHandler: fallbackHandler},
		IdleTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          stdlog.New(io.Discard, "", 0),
	}

	ln, err := net.Listen("tcp", addr)

	if err != nil {
		return nil, err
	}

	nln := &NaiveListener{
		Listener:          ln,
		maxPacingRate:     config.MaxPacingRate,
		congestionControl: config.CongestionControl,
		tlsConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: false,
		},
	}
	go func() {
		if err = srv.Serve(nln); err != nil {
			log.Errorln("naive exited %s", err.Error())
		}
	}()
	return nln, nil
}
