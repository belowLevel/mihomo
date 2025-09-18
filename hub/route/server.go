package route

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	S "github.com/kardianos/service"
	cs "github.com/metacubex/mihomo/service"
	"github.com/sagernet/cors"
)

var (
	uiPath = ""

	httpServer *http.Server
	tlsServer  *http.Server
	unixServer *http.Server
	pipeServer *http.Server

	embedMode = false
)

func SetEmbedMode(embed bool) {
	embedMode = embed
}

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

type Config struct {
	Addr        string
	TLSAddr     string
	UnixAddr    string
	PipeAddr    string
	Secret      string
	Certificate string
	PrivateKey  string
	EchKey      string
	DohServer   string
	IsDebug     bool
	Cors        Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

func ReCreateServer(cfg *Config) {
	go start(cfg)
	go startTLS(cfg)
	go startUnix(cfg)
	if inbound.SupportNamedPipe {
		go startPipe(cfg)
	}
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string, cors Cors) http.Handler {
	isDebug = true
	r := chi.NewRouter()
	cors.Apply(r)
	if isDebug {
		r.Mount("/debug", func() http.Handler {
			r := chi.NewRouter()
			r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
				debug.FreeOSMemory()
			})
			handler := middleware.Profiler
			r.Mount("/", handler())
			return r
		}())
	}
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		//if !embedMode { // disallow restart in embed mode
		//	r.Mount("/restart", restartRouter())
		//}
		//r.Mount("/upgrade", upgradeRouter())
		addExternalRouters(r)
		r.Get("/reboot", reboot)
	})

	if uiPath != "" {
		r.Group(func(r chi.Router) {
			fs := http.StripPrefix("/ui", http.FileServer(http.Dir(uiPath)))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func start(cfg *Config) {
	// first stop existing server
	if httpServer != nil {
		_ = httpServer.Close()
		httpServer = nil
	}

	// handle addr
	if len(cfg.Addr) > 0 {
		l, err := inbound.Listen("tcp", cfg.Addr)
		if err != nil {
			log.Errorln("External controller listen error: %s", err)
			return
		}
		log.Infoln("RESTful API listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		httpServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller serve error: %s", err)
		}
	}
}

func startTLS(cfg *Config) {
	// first stop existing server
	if tlsServer != nil {
		_ = tlsServer.Close()
		tlsServer = nil
	}

	// handle tlsAddr
	if len(cfg.TLSAddr) > 0 {
		cert, err := ca.LoadTLSKeyPair(cfg.Certificate, cfg.PrivateKey, C.Path)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		l, err := inbound.Listen("tcp", cfg.TLSAddr)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		log.Infoln("RESTful API tls listening at: %s", l.Addr().String())
		tlsConfig := &tlsC.Config{Time: ntp.Now}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		tlsConfig.Certificates = []tlsC.Certificate{tlsC.UCertificate(cert)}

		if cfg.EchKey != "" {
			err = ech.LoadECHKey(cfg.EchKey, tlsConfig, C.Path)
			if err != nil {
				log.Errorln("External controller tls serve error: %s", err)
				return
			}
		}
		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors),
		}
		tlsServer = server
		if err = server.Serve(tlsC.NewListenerForHttps(l, server, tlsConfig)); err != nil {
			log.Errorln("External controller tls serve error: %s", err)
		}
	}
}

func startUnix(cfg *Config) {
	// first stop existing server
	if unixServer != nil {
		_ = unixServer.Close()
		unixServer = nil
	}

	// handle addr
	if len(cfg.UnixAddr) > 0 {
		addr := C.Path.Resolve(cfg.UnixAddr)

		dir := filepath.Dir(addr)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Errorln("External controller unix listen error: %s", err)
				return
			}
		}

		// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
		//
		// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
		// a socket file is created within the filesystem. On Linux, the application is expected to unlink
		// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
		// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
		// should be used to delete the socket file prior to calling bind with the same path.
		_ = syscall.Unlink(addr)

		l, err := inbound.Listen("unix", addr)
		if err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return
		}
		_ = os.Chmod(addr, 0o666)
		log.Infoln("RESTful API unix listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		unixServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller unix serve error: %s", err)
		}
	}
}

func startPipe(cfg *Config) {
	// first stop existing server
	if pipeServer != nil {
		_ = pipeServer.Close()
		pipeServer = nil
	}

	// handle addr
	if len(cfg.PipeAddr) > 0 {
		if !strings.HasPrefix(cfg.PipeAddr, "\\\\.\\pipe\\") { // windows namedpipe must start with "\\.\pipe\"
			log.Errorln("External controller pipe listen error: windows namedpipe must start with \"\\\\.\\pipe\\\"")
			return
		}

		l, err := inbound.ListenNamedPipe(cfg.PipeAddr)
		if err != nil {
			log.Errorln("External controller pipe listen error: %s", err)
			return
		}
		log.Infoln("RESTful API pipe listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		pipeServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller pipe serve error: %s", err)
		}
	}
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, _, err = ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	cs := statistic.ChannelManager
	buf := &bytes.Buffer{}

	//proxies := tunnel.Proxies()
	//
	//selectors := make([]*outboundgroup.Selector, 0)
	//for _, proxy := range proxies {
	//	if adapterP, ok := proxy.(*adapter.Proxy); ok {
	//		adapter := adapterP.ProxyAdapter
	//		if adapterP.Type() == C.Selector {
	//			selector := adapter.(*outboundgroup.Selector)
	//			selectors = append(selectors, selector)
	//		}
	//	}
	//}

	var err error
	for range tick.C {
		buf.Reset()
		var traffics map[string]Traffic = make(map[string]Traffic)
		//for _, s := range selectors {
		//	id := s.Now()
		//	if _, ok := traffics[id]; ok {
		//		continue
		//	}
		//	if v, ok := cs[id]; ok {
		//		up, down := v.Now()
		//		traffic := Traffic{
		//			Up:   up,
		//			Down: down,
		//		}
		//		traffics[id] = traffic
		//	}
		//}
		for k, v := range cs {
			if v.HasCollections() {
				up, down := v.Now()
				traffics[k] = Traffic{
					Up:   up,
					Down: down,
				}
			}
		}

		if err := json.NewEncoder(buf).Encode(traffics); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsutil.WriteMessage(wsConn, ws.StateServerSide, ws.OpText, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, _, err = ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	buf := &bytes.Buffer{}

	for range tick.C {
		buf.Reset()

		stat, err := statistic.Processor.MemoryInfo()
		if err != nil {
			return
		}
		inuse := stat.RSS
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse: inuse,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsutil.WriteMessage(wsConn, ws.StateServerSide, ws.OpText, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, _, err = ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsutil.WriteMessage(wsConn, ws.StateServerSide, ws.OpText, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}

func reboot(w http.ResponseWriter, r *http.Request) {

	if cs.IsOpenWrt() {
		confPath := "/etc/init.d/" + cs.ServiceName
		cmd := exec.Command(confPath, "restart")
		err := cmd.Start()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	status, _ := cs.Srv.Status()
	if status == S.StatusUnknown {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		execPath, err := os.Executable()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v", err)
			return
		}
		cmd := exec.Command(execPath, "-s", "restart")
		err = cmd.Start()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
