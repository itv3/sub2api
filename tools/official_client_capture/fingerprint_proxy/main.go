// 指纹保持型采集转发器只服务于 Codex candidate MITM 矩阵。
//
// 第一层 mitmproxy 负责记录应用层 JSONL；本进程作为它的上游显式代理，终止
// mitmproxy 重建的 TLS，再用冻结的 Codex 版本画像和 uTLS 连接 ChatGPT。这样
// 既不让普通 mitmproxy 的 ClientHello 暴露给上游，也不把采集逻辑注入生产服务。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

const (
	defaultListenAddress = "127.0.0.1:18082"
	upstreamPort         = "443"
	maxProfileBytes      = 8 << 20
	minTCPMaxSegment     = 536
	maxTCPMaxSegment     = 65495
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || strings.ContainsAny(value, "/:@") {
		return errors.New("目标主机名非法")
	}
	*values = append(*values, value)
	return nil
}

type profileDocument struct {
	Version    string             `json:"Version"`
	Digest     string             `json:"Digest"`
	Transports []transportProfile `json:"Transports"`
	Endpoints  []endpointProfile  `json:"Endpoints"`
}

type transportProfile struct {
	ID                   string                     `json:"ID"`
	Protocol             string                     `json:"Protocol"`
	CipherSuites         []uint16                   `json:"CipherSuites"`
	SupportedGroups      []uint16                   `json:"SupportedGroups"`
	SignatureAlgorithms  []uint16                   `json:"SignatureAlgorithms"`
	ALPN                 []string                   `json:"ALPN"`
	Extensions           []uint16                   `json:"Extensions"`
	RandomizeExtensions  bool                       `json:"RandomizeExtensions"`
	SupportedVersions    []uint16                   `json:"SupportedVersions"`
	KeyShareGroups       []uint16                   `json:"KeyShareGroups"`
	PSKModes             []uint16                   `json:"PSKModes"`
	TLSMinVersion        uint16                     `json:"TLSMinVersion"`
	TLSMaxVersion        uint16                     `json:"TLSMaxVersion"`
	LowercaseHTTPHeaders bool                       `json:"LowercaseHTTPHeaders"`
	WebSocket            *webSocketTransportProfile `json:"WebSocket"`
}

type endpointProfile struct {
	ID                      string           `json:"ID"`
	Method                  string           `json:"Method"`
	Upgrade                 string           `json:"Upgrade"`
	TransportID             string           `json:"TransportID"`
	Host                    string           `json:"Host"`
	Path                    string           `json:"Path"`
	HeaderOrderMode         string           `json:"HeaderOrderMode"`
	Headers                 []endpointHeader `json:"Headers"`
	HeaderMapInsertionOrder []string         `json:"HeaderMapInsertionOrder"`
	PostRemoveHeaders       []string         `json:"PostRemoveHeaders"`
}

type webSocketTransportProfile struct {
	FixedHandshakePrefix []string `json:"FixedHandshakePrefix"`
}

type endpointHeader struct {
	Name string `json:"Name"`
}

type profileCatalog struct {
	document   profileDocument
	transports map[string]transportProfile
}

func loadProfileCatalog(path string, expectedVersion string) (*profileCatalog, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("画像路径必须是绝对路径")
	}
	metadata, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("读取画像元数据：%w", err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return nil, errors.New("画像必须是非符号链接普通文件")
	}
	if metadata.Size() <= 0 || metadata.Size() > maxProfileBytes {
		return nil, errors.New("画像大小超出允许范围")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取画像：%w", err)
	}
	var document profileDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("解析画像：%w", err)
	}
	if document.Version != expectedVersion || document.Version == "" {
		return nil, fmt.Errorf("画像版本不一致：%q", document.Version)
	}
	if document.Digest == "" || len(document.Transports) == 0 || len(document.Endpoints) == 0 {
		return nil, errors.New("画像身份或端点不完整")
	}
	transports := make(map[string]transportProfile, len(document.Transports))
	for _, transport := range document.Transports {
		if transport.ID == "" || transport.Protocol == "" || len(transport.CipherSuites) == 0 ||
			len(transport.Extensions) == 0 || transport.TLSMinVersion == 0 || transport.TLSMaxVersion == 0 {
			return nil, fmt.Errorf("传输画像不完整：%q", transport.ID)
		}
		if _, duplicate := transports[transport.ID]; duplicate {
			return nil, fmt.Errorf("传输画像重复：%q", transport.ID)
		}
		transports[transport.ID] = transport
	}
	for _, endpoint := range document.Endpoints {
		if endpoint.ID == "" || endpoint.Method == "" || endpoint.Path == "" || endpoint.Host == "" {
			return nil, errors.New("端点画像不完整")
		}
		if _, ok := transports[endpoint.TransportID]; !ok {
			return nil, fmt.Errorf("端点 %s 引用未知传输 %s", endpoint.ID, endpoint.TransportID)
		}
	}
	for _, transport := range document.Transports {
		if _, _, err := compileH1Rules(document.Endpoints, transport); err != nil {
			return nil, err
		}
	}
	return &profileCatalog{document: document, transports: transports}, nil
}

func isWebSocketRequest(request *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") &&
		headerContainsToken(request.Header.Values("Connection"), "upgrade")
}

func headerContainsToken(values []string, expected string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func (catalog *profileCatalog) profileFor(request *http.Request) (string, *tlsfingerprint.Profile, error) {
	if catalog == nil || request == nil || request.URL == nil {
		return "", nil, errors.New("请求或画像为空")
	}
	upgrade := ""
	if isWebSocketRequest(request) {
		upgrade = "websocket"
	}
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, endpoint := range catalog.document.Endpoints {
		if endpoint.Method != request.Method || endpoint.Path != path || endpoint.Upgrade != upgrade {
			continue
		}
		transport := catalog.transports[endpoint.TransportID]
		rules, preserveHeaderCase, err := compileH1Rules(catalog.document.Endpoints, transport)
		if err != nil {
			return "", nil, err
		}
		lowercaseHeaders := transport.LowercaseHTTPHeaders
		if transport.WebSocket != nil {
			lowercaseHeaders = true
		}
		return transport.ID, &tlsfingerprint.Profile{
			Name: "Codex " + catalog.document.Version + " 采集转发 " + transport.ID,
			Transport: tlsfingerprint.TransportOptions{
				DisableCompression: true,
				LowercaseHeaders:   lowercaseHeaders,
				PreserveHeaderCase: preserveHeaderCase,
				H1HeaderOrders:     rules,
				StrictH1Wire:       true,
			},
			CipherSuites:        append([]uint16(nil), transport.CipherSuites...),
			Curves:              append([]uint16(nil), transport.SupportedGroups...),
			SignatureAlgorithms: append([]uint16(nil), transport.SignatureAlgorithms...),
			ALPNProtocols:       append([]string(nil), transport.ALPN...),
			SupportedVersions:   append([]uint16(nil), transport.SupportedVersions...),
			KeyShareGroups:      append([]uint16(nil), transport.KeyShareGroups...),
			PSKModes:            append([]uint16(nil), transport.PSKModes...),
			Extensions:          append([]uint16(nil), transport.Extensions...),
			RandomizeExtensions: transport.RandomizeExtensions,
			TLSVersMin:          transport.TLSMinVersion,
			TLSVersMax:          transport.TLSMaxVersion,
		}, nil
	}
	return "", nil, fmt.Errorf("画像没有匹配端点：%s %s upgrade=%s", request.Method, path, upgrade)
}

func compileH1Rules(endpoints []endpointProfile, transport transportProfile) ([]tlsfingerprint.H1HeaderOrderRule, []string, error) {
	preserveHeaderCase := []string(nil)
	if transport.WebSocket != nil {
		preserveHeaderCase = append(preserveHeaderCase, transport.WebSocket.FixedHandshakePrefix...)
	}
	rules := make([]tlsfingerprint.H1HeaderOrderRule, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.TransportID != transport.ID {
			continue
		}
		desired := make([]string, 0, len(endpoint.Headers))
		for _, header := range endpoint.Headers {
			name := strings.ToLower(strings.TrimSpace(header.Name))
			if name == "" {
				return nil, nil, fmt.Errorf("端点 %s 包含空 header", endpoint.ID)
			}
			desired = append(desired, name)
		}
		rule := tlsfingerprint.H1HeaderOrderRule{
			Method:         endpoint.Method,
			Path:           endpoint.Path,
			RejectUnlisted: true,
		}
		if endpoint.Upgrade == "" {
			if endpoint.HeaderOrderMode != "h1_header_map_final_order" && endpoint.HeaderOrderMode != "explicit_order" {
				return nil, nil, fmt.Errorf("端点 %s 的 HTTP header 次序模式非法", endpoint.ID)
			}
			rule.Mode = tlsfingerprint.H1HeaderOrderModeStatic
			rule.Order = desired
			rules = append(rules, rule)
			continue
		}
		if transport.WebSocket == nil || endpoint.HeaderOrderMode != "ws_fixed_prefix_then_header_map_swap_remove" {
			return nil, nil, fmt.Errorf("端点 %s 的 WebSocket header 次序模式非法", endpoint.ID)
		}
		prefix := lowerHeaderNames(transport.WebSocket.FixedHandshakePrefix)
		initialOrder := lowerHeaderNames(endpoint.HeaderMapInsertionOrder)
		appendHeaders := lowerHeaderNames(endpoint.PostRemoveHeaders)
		if len(prefix) == 0 || len(initialOrder) < len(prefix) || len(desired) < len(prefix) {
			return nil, nil, fmt.Errorf("端点 %s 的 WebSocket 构造序不完整", endpoint.ID)
		}
		for index := range prefix {
			if desired[index] != prefix[index] || initialOrder[index] != prefix[index] {
				return nil, nil, fmt.Errorf("端点 %s 的 WebSocket 固定前缀不一致", endpoint.ID)
			}
		}
		rule.Mode = tlsfingerprint.H1HeaderOrderModeSwapRemove
		rule.Order = initialOrder
		rule.PrefixHeaders = append([]string(nil), prefix...)
		rule.RemoveHeaders = append([]string(nil), prefix...)
		rule.AppendHeaders = appendHeaders
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("传输 %s 没有 H1 端点规则", transport.ID)
	}
	return rules, preserveHeaderCase, nil
}

func lowerHeaderNames(names []string) []string {
	result := make([]string, len(names))
	for index, name := range names {
		result[index] = strings.ToLower(strings.TrimSpace(name))
	}
	return result
}

type fingerprintTransport struct {
	catalog       *profileCatalog
	tcpDialer     *net.Dialer
	tcpMaxSegment int
	mu            sync.Mutex
	items         map[string]*http.Transport
}

func newFingerprintTransport(catalog *profileCatalog, tcpMaxSegment int) *fingerprintTransport {
	dialer := &net.Dialer{
		Control: func(_, _ string, rawConnection syscall.RawConn) error {
			var socketError error
			if err := rawConnection.Control(func(descriptor uintptr) {
				socketError = unix.SetsockoptInt(
					int(descriptor),
					unix.IPPROTO_TCP,
					unix.TCP_MAXSEG,
					tcpMaxSegment,
				)
			}); err != nil {
				return fmt.Errorf("访问上游 TCP socket：%w", err)
			}
			if socketError != nil {
				return fmt.Errorf("设置上游 TCP_MAXSEG：%w", socketError)
			}
			return nil
		},
	}
	return &fingerprintTransport{
		catalog:       catalog,
		tcpDialer:     dialer,
		tcpMaxSegment: tcpMaxSegment,
		items:         make(map[string]*http.Transport),
	}
}

func (transport *fingerprintTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transportID, profile, err := transport.catalog.profileFor(request)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	item := transport.items[transportID]
	if item == nil {
		item = &http.Transport{
			MaxIdleConns:          8,
			MaxIdleConnsPerHost:   4,
			MaxConnsPerHost:       4,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: 90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ForceAttemptHTTP2:     false,
			DisableCompression:    true,
			DialTLSContext:        tlsfingerprint.NewDialer(profile, transport.tcpDialer.DialContext).DialTLSContext,
		}
		transport.items[transportID] = item
	}
	transport.mu.Unlock()
	return item.RoundTrip(request)
}

func (transport *fingerprintTransport) CloseIdleConnections() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, item := range transport.items {
		item.CloseIdleConnections()
	}
}

type captureProxy struct {
	targets      map[string]struct{}
	certificate  tls.Certificate
	transport    http.RoundTripper
	errorLogger  *log.Logger
	handshakeTTL time.Duration
}

func (proxy *captureProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		http.Error(writer, "只允许 CONNECT", http.StatusMethodNotAllowed)
		return
	}
	target, err := normalizeConnectTarget(request.Host)
	if err != nil {
		http.Error(writer, "CONNECT 目标非法", http.StatusBadRequest)
		return
	}
	host, _, _ := net.SplitHostPort(target)
	if _, ok := proxy.targets[strings.ToLower(host)]; !ok {
		http.Error(writer, "CONNECT 目标不在白名单", http.StatusForbidden)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "服务端不支持连接接管", http.StatusInternalServerError)
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = connection.Close()
		return
	}
	if err := buffer.Flush(); err != nil {
		_ = connection.Close()
		return
	}
	proxy.serveTunnel(connection, target)
}

func normalizeConnectTarget(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || port != upstreamPort {
		return "", errors.New("CONNECT 只允许显式 443 端口")
	}
	if net.ParseIP(host) != nil || strings.ContainsAny(host, "/@") {
		return "", errors.New("CONNECT 只允许 DNS 主机名")
	}
	return net.JoinHostPort(strings.ToLower(host), port), nil
}

func (proxy *captureProxy) serveTunnel(connection net.Conn, target string) {
	tlsConnection := tls.Server(connection, &tls.Config{
		Certificates: []tls.Certificate{proxy.certificate},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	_ = tlsConnection.SetDeadline(time.Now().Add(proxy.handshakeTTL))
	if err := tlsConnection.Handshake(); err != nil {
		_ = connection.Close()
		return
	}
	_ = tlsConnection.SetDeadline(time.Time{})
	handler := proxy.reverseHandler(target)
	if tlsConnection.ConnectionState().NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(tlsConnection, &http2.ServeConnOpts{Handler: handler})
		return
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	_ = server.Serve(newSingleConnectionListener(tlsConnection))
}

func (proxy *captureProxy) reverseHandler(target string) http.Handler {
	upstream := &url.URL{Scheme: "https", Host: target}
	host, _, _ := net.SplitHostPort(target)
	reverse := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(upstream)
			request.Out.Host = host
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("Proxy-Connection")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
		},
		Transport:     proxy.transport,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			path := "/"
			if request != nil && request.URL != nil && request.URL.EscapedPath() != "" {
				path = request.URL.EscapedPath()
			}
			proxy.errorLogger.Printf(
				"上游转发失败 method=%s path=%s reason=%s",
				request.Method,
				path,
				classifyUpstreamError(err),
			)
			http.Error(writer, "上游转发失败", http.StatusBadGateway)
		},
	}
	return reverse
}

func classifyUpstreamError(err error) string {
	if err == nil {
		return "unknown"
	}
	message := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled) || strings.Contains(message, "context canceled"):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded"):
		return "timeout"
	case strings.Contains(message, "official h1 wire"):
		return "h1-profile-mismatch"
	case strings.Contains(message, "apply tls preset"):
		return "tls-preset"
	case strings.Contains(message, "certificate") || strings.Contains(message, "unknown authority"):
		return "tls-certificate"
	case errors.Is(err, io.EOF) || strings.Contains(message, "connection reset") || strings.Contains(message, "server closed") || strings.HasSuffix(message, "eof"):
		return "upstream-closed"
	case strings.Contains(message, "tls handshake"):
		return "tls-handshake"
	case strings.Contains(message, "no such host"):
		return "dns"
	case strings.Contains(message, "network is unreachable"):
		return "route"
	case strings.Contains(message, "connection refused"):
		return "connection-refused"
	default:
		return "other"
	}
}

type trackedConnection struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (connection *trackedConnection) Close() error {
	connection.once.Do(func() { close(connection.done) })
	return connection.Conn.Close()
}

type singleConnectionListener struct {
	connection *trackedConnection
	mu         sync.Mutex
	accepted   bool
}

func newSingleConnectionListener(connection net.Conn) net.Listener {
	return &singleConnectionListener{connection: &trackedConnection{Conn: connection, done: make(chan struct{})}}
}

func (listener *singleConnectionListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if !listener.accepted {
		listener.accepted = true
		connection := listener.connection
		listener.mu.Unlock()
		return connection, nil
	}
	done := listener.connection.done
	listener.mu.Unlock()
	<-done
	return nil, net.ErrClosed
}

func (listener *singleConnectionListener) Close() error { return nil }

func (listener *singleConnectionListener) Addr() net.Addr { return listener.connection.LocalAddr() }

func ephemeralCertificate(hosts []string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     append([]string(nil), hosts...),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(6 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	)
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("codex-fingerprint-capture-proxy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listenAddress := flags.String("listen", defaultListenAddress, "监听地址")
	profilePath := flags.String("profile", "", "冻结画像绝对路径")
	expectedVersion := flags.String("version", "", "目标 Codex 完整版本")
	tcpMaxSegment := flags.Int("tcp-max-segment", 0, "上游 socket 的 TCP_MAXSEG")
	validateOnly := flags.Bool("validate-only", false, "只校验画像和二进制")
	var targetHosts stringList
	flags.Var(&targetHosts, "target-host", "允许的上游主机，可重复")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *profilePath == "" || *expectedVersion == "" || len(targetHosts) == 0 {
		return errors.New("必须提供 --profile、--version、--tcp-max-segment 和至少一个 --target-host")
	}
	if *tcpMaxSegment < minTCPMaxSegment || *tcpMaxSegment > maxTCPMaxSegment {
		return fmt.Errorf(
			"--tcp-max-segment 必须为 %d～%d",
			minTCPMaxSegment,
			maxTCPMaxSegment,
		)
	}
	catalog, err := loadProfileCatalog(*profilePath, *expectedVersion)
	if err != nil {
		return err
	}
	if *validateOnly {
		fmt.Printf("fingerprint_proxy_valid=true profile_version=%s profile_digest=%s tcp_max_segment=%d\n", catalog.document.Version, catalog.document.Digest, *tcpMaxSegment)
		return nil
	}
	certificate, err := ephemeralCertificate(targetHosts)
	if err != nil {
		return fmt.Errorf("创建临时终止证书：%w", err)
	}
	targets := make(map[string]struct{}, len(targetHosts))
	for _, host := range targetHosts {
		targets[host] = struct{}{}
	}
	transport := newFingerprintTransport(catalog, *tcpMaxSegment)
	proxy := &captureProxy{
		targets:      targets,
		certificate:  certificate,
		transport:    transport,
		errorLogger:  log.New(os.Stderr, "fingerprint-proxy: ", log.LstdFlags|log.LUTC),
		handshakeTTL: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("监听：%w", err)
	}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	stopContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-stopContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	fmt.Printf("fingerprint_proxy_ready=%s profile_version=%s tcp_max_segment=%d\n", listener.Addr(), catalog.document.Version, *tcpMaxSegment)
	err = server.Serve(listener)
	transport.CloseIdleConnections()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Codex 指纹保持型采集转发器失败："+err.Error())
		os.Exit(1)
	}
}
