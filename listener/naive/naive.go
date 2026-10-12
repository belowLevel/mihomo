package naive

import (
	"crypto/tls"
	"errors"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/pires/go-proxyproto"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

type Config struct {
	Users                     []string `inbound:"users"`
	Certificate               string   `inbound:"certificate"`
	PrivateKey                string   `inbound:"private-key"`
	CongestionControl         string   `inbound:"congestion-control,omitempty"`
	MaxPacingRate             uint64   `inbound:"max-pacing-rate,omitempty"`
	Fallback                  string   `inbound:"fallback"`
	ProxyprotoAllowFromRanges []string `inbound:"proxyproto-allow-from-ranges,omitempty"`
}
type NaiveListener struct {
	net.Listener
	maxPacingRate     uint64
	congestionControl string
	tlsConfig         *tls.Config
}

func (n *NaiveListener) Accept() (net.Conn, error) {
	conn, err := n.Listener.Accept()
	pc := conn.(*proxyproto.Conn)
	err2 := common.SetCongestionMaxPacingRate(pc.Raw(), n.congestionControl, n.maxPacingRate)
	if err2 != nil {
		log.Errorln("%s", err2.Error())
	}
	tlsConn := tls.Server(pc, n.tlsConfig)
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
	if errors.Is(err, errNotHaveAuthorizationHeader) {
		s, _ := httputil.DumpRequest(r, false)
		log.Warnln("from %s, %s", r.RemoteAddr, string(s))
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

	connPolicy, err := proxyproto.PolicyFromRanges(config.ProxyprotoAllowFromRanges, proxyproto.USE, proxyproto.REJECT)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)

	if err != nil {
		return nil, err
	}

	pl := &proxyproto.Listener{
		Listener:   ln,
		ConnPolicy: connPolicy,
	}
	nln := &NaiveListener{
		Listener:          pl,
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
