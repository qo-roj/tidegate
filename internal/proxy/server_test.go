package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/audit"
	"github.com/qo-roj/tidegate/internal/route"
	"github.com/qo-roj/tidegate/internal/rules"
)

// makeTestServer creates a proxy Server with a test router.
// Returns the server and a mock upstream that records what it receives.
func makeTestServer(t *testing.T) (*Server, *mockUpstream) {
	cfg := &rules.Config{
		Blocks:    []string{"/etc/shadow"},
		LocalOnly: []string{"**/.env"},
		Redact:    []string{"/var/log/**"},
	}
	rs := rules.BuildRuleSet(cfg, "test")

	// Use a temp audit log
	auditLog, err := audit.New(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLog.Close() })

	router := route.New(rs, nil, auditLog)

	// Mock upstream that echoes back what it receives
	upstream := &mockUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.handle))

	// Override the upstream routes to point at our mock.
	// The proxy hardcodes https://, so we use a custom transport
	// that rewrites to the mock's http:// URL.
	oldRoutes := UpstreamRoutes
	UpstreamRoutes = map[string]string{
		"/anthropic": "mock-upstream.test",
		"/openai":    "mock-upstream.test",
	}
	t.Cleanup(func() {
		UpstreamRoutes = oldRoutes
		upstream.server.Close()
	})

	// Override the upstream client to use a transport that rewrites
	// https://mock-upstream.test to the mock's http:// URL
	originalClient := upstreamClient
	upstreamClient = &http.Client{
		Transport: &mockTransport{upstream: upstream},
		Timeout:   1000000000, // avoid timeout during test
	}
	t.Cleanup(func() { upstreamClient = originalClient })

	srv := New(router, auditLog, 0)

	return srv, upstream
}

// mockTransport rewrites https:// requests to the mock upstream's http:// URL.
type mockTransport struct {
	upstream *mockUpstream
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point at the mock server
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(m.upstream.server.URL, "http://")
	req.RequestURI = ""
	return http.DefaultTransport.RoundTrip(req)
}

// mockUpstream records received requests and returns configurable responses.
type mockUpstream struct {
	server          *httptest.Server
	receivedBody    []byte
	receivedPath    string
	receivedHeaders http.Header
	responseBody    string
	statusCode      int
}

func (m *mockUpstream) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.receivedBody = body
	m.receivedPath = r.URL.Path
	m.receivedHeaders = r.Header.Clone()

	resp := m.responseBody
	if resp == "" {
		resp = `{"content": "OK"}`
	}
	if m.statusCode == 0 {
		m.statusCode = 200
	}
	w.WriteHeader(m.statusCode)
	w.Write([]byte(resp))
}

// makeChatRequest creates an HTTP request to the proxy.
func makeChatRequest(t *testing.T, body string, provider string) *http.Request {
	req := httptest.NewRequest("POST", "/"+provider+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tidegate-Agent", "test-agent")
	req.Header.Set("Authorization", "Bearer test-key")
	return req
}

// makeChatBody creates a chat request body with the given messages.
func makeChatBody(t *testing.T, messages []map[string]interface{}) string {
	body, err := json.Marshal(map[string]interface{}{
		"model":    "test-model",
		"messages": messages,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestProxyPublicContentPassesThrough(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "Hello from the cloud"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "What is 2+2?"},
	}), "openai")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Upstream should have received the original content
	var received map[string]interface{}
	json.Unmarshal(upstream.receivedBody, &received)
	messages := received["messages"].([]interface{})
	msg0 := messages[0].(map[string]interface{})
	if msg0["content"] != "What is 2+2?" {
		t.Errorf("upstream got wrong content: %v", msg0["content"])
	}

	// Response should pass through
	if !strings.Contains(rec.Body.String(), "Hello from the cloud") {
		t.Error("response should contain upstream content")
	}
}

func TestProxyRedactsPIIBeforeForwarding(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "response"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "Check /var/log/syslog with IP 203.0.113.42"},
	}), "openai")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// Upstream should NOT have received the raw IP
	receivedStr := string(upstream.receivedBody)
	if strings.Contains(receivedStr, "203.0.113.42") {
		t.Error("upstream should not receive raw IP")
	}
	if !strings.Contains(receivedStr, "[TG:IP:") {
		t.Error("upstream should receive redacted token")
	}
}

func TestProxyRestoresTokensInResponse(t *testing.T) {
	srv, upstream := makeTestServer(t)

	// Request has a redacted IP
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "Check /var/log/syslog with IP 203.0.113.42"},
	}), "openai")

	// Upstream response echoes the token back
	upstream.responseBody = `{"content": "The IP [TG:IP:1:00000000] is reachable"}`

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// Response should have the token restored to the real IP
	if !strings.Contains(rec.Body.String(), "203.0.113.42") {
		t.Errorf("response should restore IP, got: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "[TG:IP:") {
		t.Error("response should not contain raw token")
	}
}

func TestProxyBlockedContentReplacedWithMessage(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "response"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "I read /etc/shadow and found hashes"},
	}), "openai")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// Upstream should NOT receive the raw content
	receivedStr := string(upstream.receivedBody)
	if strings.Contains(receivedStr, "I read /etc/shadow") {
		t.Error("upstream should not receive blocked content")
	}
	if !strings.Contains(receivedStr, "access denied") {
		t.Error("upstream should receive block message")
	}
}

func TestProxyFailClosedOnRouterError(t *testing.T) {
	// Create a server with a nil router to trigger an error
	srv := &Server{
		Router:   nil,
		AuditLog: nil,
		Port:     0,
	}

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "test"},
	}), "openai")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// Should get 502, not passthrough
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestProxyStripsPathPrefix(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "OK"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "anthropic")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// Upstream should receive the path WITHOUT the /anthropic prefix
	if upstream.receivedPath != "/v1/chat/completions" {
		t.Errorf("expected /v1/chat/completions, got %s", upstream.receivedPath)
	}
}

func TestProxyFiltersTidegateAgentHeader(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "OK"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set("Cookie", "session=secret")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// X-Tidegate-Agent should NOT be forwarded
	if upstream.receivedHeaders.Get("X-Tidegate-Agent") != "" {
		t.Error("X-Tidegate-Agent should be stripped")
	}
	// Cookie should NOT be forwarded
	if upstream.receivedHeaders.Get("Cookie") != "" {
		t.Error("Cookie should be stripped")
	}
	// Authorization SHOULD be forwarded
	if upstream.receivedHeaders.Get("Authorization") != "Bearer test-key" {
		t.Error("Authorization should be forwarded")
	}
}

func TestProxyFiltersHopByHopHeaders(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.responseBody = `{"content": "OK"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Upgrade", "h2c")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if upstream.receivedHeaders.Get("Connection") != "" {
		t.Error("Connection should be stripped")
	}
	if upstream.receivedHeaders.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding should be stripped")
	}
	if upstream.receivedHeaders.Get("Upgrade") != "" {
		t.Error("Upgrade should be stripped")
	}
}

func TestProxyUnknownProviderReturnsError(t *testing.T) {
	srv, _ := makeTestServer(t)

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "unknown-provider")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for unknown provider, got %d", rec.Code)
	}
}

func TestProxySegmentMatchingPreventsPrefixAttack(t *testing.T) {
	srv, _ := makeTestServer(t)

	// /anthropicevil should NOT match /anthropic
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "anthropicevil")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for /anthropicevil, got %d", rec.Code)
	}
}

func TestProxyHealthEndpoint(t *testing.T) {
	srv, _ := makeTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.HealthCheck(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
}

func TestProxyStreamingResponseRestoresTokens(t *testing.T) {
	srv, upstream := makeTestServer(t)

	// Request has a redacted IP
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "Check /var/log/syslog with IP 203.0.113.42"},
	}), "openai")

	// Upstream returns SSE with the token split across chunks
	upstream.responseBody = "data: {\"content\": \"IP [TG:IP:1:00000000]\"}\n\ndata: [DONE]\n\n"
	upstream.statusCode = 200

	// Override upstream handler to return SSE
	upstream.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstream.receivedBody = body
		upstream.receivedHeaders = r.Header.Clone()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// Send the token split across two writes
		w.Write([]byte("data: {\"content\": \"IP [TG:IP"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		w.Write([]byte(":1:00000000] is reachable\"}\n\ndata: [DONE]\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	// The streaming response should have the token restored
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.42") {
		t.Errorf("streaming response should restore IP, got: %s", body)
	}
	if strings.Contains(body, "[TG:IP:") {
		t.Error("streaming response should not contain raw token")
	}
}

func TestProxyConcurrentRequestsNoCrossContamination(t *testing.T) {
	srv, upstream := makeTestServer(t)

	// Use a stateless upstream handler that returns [TG:IP:1:00000000] for each request.
	// Don't write to shared upstream fields to avoid data races.
	upstream.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"content": "response with [TG:IP:1:00000000]"}`))
	})

	// Send two concurrent requests with different IPs
	bodyA := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "Check /var/log/syslog with IP 203.0.113.42"},
	})
	bodyB := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "Check /var/log/auth.log with IP 10.0.0.5"},
	})

	done := make(chan error, 2)

	go func() {
		req := makeChatRequest(t, bodyA, "openai")
		rec := httptest.NewRecorder()
		srv.handleProxy(rec, req)
		if !strings.Contains(rec.Body.String(), "203.0.113.42") {
			done <- &proxyTestErr{"request A got wrong IP restored: " + rec.Body.String()}
			return
		}
		done <- nil
	}()

	go func() {
		req := makeChatRequest(t, bodyB, "openai")
		rec := httptest.NewRecorder()
		srv.handleProxy(rec, req)
		if !strings.Contains(rec.Body.String(), "10.0.0.5") {
			done <- &proxyTestErr{"request B got wrong IP restored: " + rec.Body.String()}
			return
		}
		done <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

func TestProxyForwardsUpstreamErrorStatus(t *testing.T) {
	srv, upstream := makeTestServer(t)
	upstream.statusCode = 429
	upstream.responseBody = `{"error": "rate limited"}`

	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")

	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != 429 {
		t.Errorf("expected 429, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rate limited") {
		t.Error("should forward error body")
	}
}

type proxyTestErr struct{ msg string }

func (e *proxyTestErr) Error() string { return e.msg }
