package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testProfileDocument() profileDocument {
	return profileDocument{
		Version: "0.151.0",
		Digest:  strings.Repeat("a", 64),
		Transports: []transportProfile{
			{
				ID: "http-profile", Protocol: "http/1.1", CipherSuites: []uint16{0x1301},
				SupportedGroups: []uint16{29}, SignatureAlgorithms: []uint16{0x0403},
				Extensions: []uint16{0, 10, 13, 43, 51}, SupportedVersions: []uint16{0x0304},
				KeyShareGroups: []uint16{29}, PSKModes: []uint16{1},
				TLSMinVersion: 0x0303, TLSMaxVersion: 0x0304,
			},
			{
				ID: "ws-profile", Protocol: "websocket", CipherSuites: []uint16{0x1301},
				SupportedGroups: []uint16{29}, SignatureAlgorithms: []uint16{0x0403},
				Extensions: []uint16{0, 10, 13, 43, 51}, SupportedVersions: []uint16{0x0304},
				KeyShareGroups: []uint16{29}, PSKModes: []uint16{1},
				TLSMinVersion: 0x0303, TLSMaxVersion: 0x0304, RandomizeExtensions: true,
				WebSocket: &webSocketTransportProfile{FixedHandshakePrefix: []string{
					"Host", "Connection", "Upgrade", "Sec-WebSocket-Version", "Sec-WebSocket-Key",
				}},
			},
		},
		Endpoints: []endpointProfile{
			{
				ID: "models", Method: "GET", TransportID: "http-profile", Host: "chatgpt.com",
				Path: "/backend-api/codex/models", HeaderOrderMode: "h1_header_map_final_order",
				Headers: []endpointHeader{{Name: "version"}, {Name: "host"}},
			},
			{
				ID: "oauth_refresh", Method: "POST", TransportID: "http-profile", Host: "auth.openai.com",
				Path: "/oauth/token", HeaderOrderMode: "explicit_order",
				Headers: []endpointHeader{{Name: "content-type"}, {Name: "host"}},
			},
			{
				ID: "responses_ws", Method: "GET", Upgrade: "websocket", TransportID: "ws-profile",
				Host: "chatgpt.com", Path: "/backend-api/codex/responses",
				HeaderOrderMode: "ws_fixed_prefix_then_header_map_swap_remove",
				Headers: []endpointHeader{
					{Name: "host"}, {Name: "connection"}, {Name: "upgrade"},
					{Name: "sec-websocket-version"}, {Name: "sec-websocket-key"},
					{Name: "authorization"}, {Name: "sec-websocket-extensions"},
				},
				HeaderMapInsertionOrder: []string{
					"host", "connection", "upgrade", "sec-websocket-version", "sec-websocket-key", "authorization",
				},
				PostRemoveHeaders: []string{"sec-websocket-extensions"},
			},
		},
	}
}

func TestLoadProfileAndSelectTransport(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "profile.json")
	raw, err := json.Marshal(testProfileDocument())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := loadProfileCatalog(path, "0.151.0")
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("GET", "https://chatgpt.com/backend-api/codex/models?client_version=0.151.0", nil)
	id, profile, err := catalog.profileFor(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	if id != "http-profile" || profile.RandomizeExtensions {
		t.Fatalf("HTTP 画像选择错误：id=%s random=%v", id, profile.RandomizeExtensions)
	}
	if !profile.Transport.StrictH1Wire || len(profile.Transport.H1HeaderOrders) != 2 {
		t.Fatalf("HTTP H1 规则未冻结：%+v", profile.Transport)
	}
	wsRequest := httptest.NewRequest("GET", "https://chatgpt.com/backend-api/codex/responses", nil)
	wsRequest.Header.Set("Connection", "keep-alive, Upgrade")
	wsRequest.Header.Set("Upgrade", "websocket")
	id, profile, err = catalog.profileFor(wsRequest)
	if err != nil {
		t.Fatal(err)
	}
	if id != "ws-profile" || !profile.RandomizeExtensions {
		t.Fatalf("WS 画像选择错误：id=%s random=%v", id, profile.RandomizeExtensions)
	}
	if len(profile.Transport.PreserveHeaderCase) != 5 || profile.Transport.H1HeaderOrders[0].Mode != "swap_remove" {
		t.Fatalf("WS H1 规则未冻结：%+v", profile.Transport)
	}
}

func TestFingerprintTransportUsesScopedTCPMaxSegmentDialer(t *testing.T) {
	transport := newFingerprintTransport(&profileCatalog{}, 1368)
	if transport.tcpMaxSegment != 1368 {
		t.Fatalf("TCP_MAXSEG 未冻结到指纹转发器：%d", transport.tcpMaxSegment)
	}
	if transport.tcpDialer == nil || transport.tcpDialer.Control == nil {
		t.Fatal("指纹转发器没有安装 socket 级 TCP_MAXSEG 控制")
	}
}

func TestFrozenProfileWritesModelsAndResponsesOverTLS(t *testing.T) {
	profilePath, err := filepath.Abs(filepath.Join(
		"..", "..", "..", "backend", "internal", "officialegress", "catalogdata",
		"runtime", "profiles", "0.151.0",
		"dbc65378c80a2ad843ce1ba6253a2e47f0dd5d8bc812bb536a2d24ddb7a59e39.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loadProfileCatalog(profilePath, "0.151.0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers []string
	}{
		{
			name: "models", method: http.MethodGet,
			path: "/backend-api/codex/models?client_version=0.151.0",
			headers: []string{
				"version", "authorization", "chatgpt-account-id", "accept", "originator", "user-agent",
			},
		},
		{
			name: "responses", method: http.MethodPost,
			path: "/backend-api/codex/responses", body: "{}",
			headers: []string{
				"version", "x-codex-beta-features", "x-codex-window-id", "x-codex-turn-metadata",
				"x-openai-internal-codex-responses-lite", "x-codex-routing-hint", "x-client-request-id",
				"session-id", "thread-id", "accept", "content-encoding", "content-type",
				"authorization", "chatgpt-account-id", "originator", "user-agent",
			},
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			request, err := http.NewRequest(current.method, server.URL+current.path, strings.NewReader(current.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "chatgpt.com"
			for _, name := range current.headers {
				request.Header.Set(name, "test")
			}
			_, profile, err := catalog.profileFor(request)
			if err != nil {
				t.Fatal(err)
			}
			profile.RootCAs = roots
			transport := &http.Transport{
				DisableCompression: true,
				ForceAttemptHTTP2:  false,
				DialTLSContext:     tlsfingerprint.NewDialer(profile, nil).DialTLSContext,
			}
			defer transport.CloseIdleConnections()
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("响应状态错误：%s", response.Status)
			}
		})
	}
}

func TestConnectTunnelForwardsStreamingHTTP(t *testing.T) {
	certificate, err := ephemeralCertificate([]string{"chatgpt.com"})
	if err != nil {
		t.Fatal(err)
	}
	proxy := &captureProxy{
		targets:     map[string]struct{}{"chatgpt.com": {}},
		certificate: certificate,
		transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Scheme != "https" || request.URL.Host != "chatgpt.com:443" {
				t.Fatalf("上游 URL 非预期：%s", request.URL.String())
			}
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader("data: ok\n\n")),
				Request:    request,
			}, nil
		}),
		errorLogger:  log.New(io.Discard, "", 0),
		handshakeTTL: time.Second,
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	count, err := connection.Read(buffer)
	if err != nil || !strings.Contains(string(buffer[:count]), "200 Connection Established") {
		t.Fatalf("CONNECT 响应错误：%q err=%v", string(buffer[:count]), err)
	}
	tlsConnection := tls.Client(connection, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // #nosec G402 -- 测试临时自签证书。
	if err := tlsConnection.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConnection, "GET /backend-api/codex/models HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(tlsConnection)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "200 OK") || !strings.Contains(string(raw), "data: ok") {
		t.Fatalf("隧道响应错误：%q", string(raw))
	}
}

func TestNormalizeConnectTargetRejectsUnsafeTargets(t *testing.T) {
	for _, value := range []string{"chatgpt.com", "chatgpt.com:80", "127.0.0.1:443", "user@chatgpt.com:443"} {
		if _, err := normalizeConnectTarget(value); err == nil {
			t.Fatalf("非法 CONNECT 目标未拒绝：%s", value)
		}
	}
	if actual, err := normalizeConnectTarget("CHATGPT.COM:443"); err != nil || actual != "chatgpt.com:443" {
		t.Fatalf("合法 CONNECT 目标未规范化：%q err=%v", actual, err)
	}
}

func TestClassifyUpstreamErrorDoesNotExposeDetails(t *testing.T) {
	tests := map[string]struct {
		err      error
		expected string
	}{
		"取消":      {err: context.Canceled, expected: "canceled"},
		"超时":      {err: context.DeadlineExceeded, expected: "timeout"},
		"H1":      {err: errors.New("official h1 wire request does not match immutable profile"), expected: "h1-profile-mismatch"},
		"TLS":     {err: errors.New("TLS handshake failed: secret detail"), expected: "tls-handshake"},
		"TLS EOF": {err: errors.New("TLS handshake failed: EOF"), expected: "upstream-closed"},
		"TLS 证书":  {err: errors.New("TLS handshake failed: certificate signed by unknown authority"), expected: "tls-certificate"},
	}
	for name, current := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := classifyUpstreamError(current.err); actual != current.expected {
				t.Fatalf("错误分类不一致：got=%s want=%s", actual, current.expected)
			}
		})
	}
}
