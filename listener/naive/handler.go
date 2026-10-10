package naive

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	errAuthFailed                 = errors.New("auth failed")
	errNotSuppordedProtoMajor     = errors.New("not supporded protoMajor")
	errNotSuppordedMethod         = errors.New("not supported metthod")
	errNotHaveAuthorizationHeader = errors.New("notHaveAuthorizationHeader")
	errAuthTypeNotSupported       = errors.New("auth type is not supported")
	errMustPadding                = errors.New("must padding")
)

type naiveHandler struct {
	authCredentials [][]byte
	config          *Config
	tunnel          C.Tunnel
	additions       []inbound.Addition
}

func (h *naiveHandler) checkCredentials(r *http.Request) error {
	if len(h.authCredentials) == 0 {
		return nil
	}
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return errNotHaveAuthorizationHeader
	}
	if strings.ToLower(pa[0]) != "basic" {
		return errAuthTypeNotSupported
	}
	for _, creds := range h.authCredentials {
		if subtle.ConstantTimeCompare(creds, []byte(pa[1])) == 1 {
			// Please do not consider this to be timing-attack-safe code. Simple equality is almost
			// mindlessly substituted with constant time algo and there ARE known issues with this code,
			// e.g. size of smallest credentials is guessable. TODO: protect from all the attacks! Hash?
			return nil
		}
	}
	return errAuthFailed
}

func (h *naiveHandler) naiveServe(w http.ResponseWriter, r *http.Request) error {
	//dumpRequest(r)
	var err error
	err = h.checkCredentials(r)
	if err != nil {
		return err
	}
	//"HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1
	if r.ProtoMajor != 1 && r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		log.Warnln("not supporded protoMajor %d", r.ProtoMajor)
		return errNotSuppordedProtoMajor
	}

	if r.Method == http.MethodConnect {
		if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				log.Warnln("CONNECT request has :scheme and/or :path pseudo-header fields")
				return errNotSuppordedMethod
			}
		}

		padding := r.Header.Get("Padding") != ""
		if !padding && h.config.MustPadding {
			return errMustPadding
		}

		// HTTP CONNECT Fast Open: Directly responds with a 200 OK
		// before attempting to connect to origin to reduce response latency.
		// We merely close the connection if Open fails.
		if r.ProtoMajor > 1 {
			// Creates a padding header with length in [30, 30+32)
			if padding {
				paddingLen := rand.Intn(32) + 30
				padding := make([]byte, paddingLen)
				bits := rand.Uint64()
				for i := range 16 {
					// Codes that won't be Huffman coded.
					padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
					bits >>= 4
				}
				for i := 16; i < paddingLen; i++ {
					padding[i] = '~'
				}
				w.Header().Set("Padding", string(padding))
			}

			w.WriteHeader(http.StatusOK)
			err := http.NewResponseController(w).Flush()
			if err != nil {
				return nil
			}
		}
		hostPort := r.URL.Host
		if hostPort == "" {
			hostPort = r.Host
		}

		if r.ProtoMajor == 1 {
			return errNotSuppordedMethod
		}

		conn := &naiveH2Conn{
			reader:        r.Body,
			writer:        w,
			flusher:       w.(http.Flusher),
			remoteAddress: M.ParseSocksaddr(r.RemoteAddr).Unwrap(),
		}

		host, port, _ := net.SplitHostPort(hostPort)
		if port == "" {
			port = "80"
		}
		// trim FQDN (#737)
		host = strings.TrimRight(host, ".")
		metadata := &C.Metadata{}
		_ = metadata.SetRemoteAddress(net.JoinHostPort(host, port))
		metadata.Type = C.NAIVE
		metadata.RawSrcAddr = conn.RemoteAddr()
		metadata.RawDstAddr = conn.LocalAddr()
		inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(conn.RemoteAddr()), inbound.WithInAddr(conn.LocalAddr()))
		inbound.ApplyAdditions(metadata, h.additions...)

		h.tunnel.HandleTCPConn(conn, metadata)
		return nil
	}
	return errNotSuppordedMethod
}

func NewNaiveHandler(users []string, config *Config, tunnel C.Tunnel, additions []inbound.Addition) *naiveHandler {
	h := &naiveHandler{
		config:    config,
		tunnel:    tunnel,
		additions: additions,
	}
	for _, v := range users {
		h.authCredentials = append(h.authCredentials, EncodeAuthCredentials(v))
	}

	return h
}

func EncodeAuthCredentials(BasicAuth string) (result []byte) {
	raw := []byte(BasicAuth)
	result = make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(result, raw)
	return
}

type fallbackHandler struct {
	reverseProxy *httputil.ReverseProxy
}

func (h *fallbackHandler) httpServe(w http.ResponseWriter, r *http.Request) {
	h.reverseProxy.ServeHTTP(w, r)
}

func NewFallbackHandler(rawURL string) (*fallbackHandler, error) {
	url, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(url)
	reverseProxy.Director = func(req *http.Request) {
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.Host = url.Host
	}
	reverseProxy.Transport = &http.Transport{
		DialContext:         dialer.NewDialer().DialContext,
		MaxIdleConns:        5000,
		MaxIdleConnsPerHost: 2000,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   false,
	}
	return &fallbackHandler{
		reverseProxy: reverseProxy,
	}, nil
}
