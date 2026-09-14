package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/route"
	"github.com/qo-roj/tidegate/internal/rules"
)

// makeGatewayTestServer creates a proxy Server in gateway mode (client keys
// required) wired to a mock upstream.
func makeGatewayTestServer(t *testing.T) (*Server, *mockUpstream) {
	srv, upstream := makeTestServer(t)
	srv.Clients = []Client{
		{Name: "phone", Key: "key-phone-123"},
		{Name: "laptop", Key: "key-laptop-456"},
	}
	return srv, upstream
}

func TestGatewayRejectsMissingKey(t *testing.T) {
	srv, _ := makeGatewayTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("want unauthorized message, got %q", rec.Body.String())
	}
}

func TestGatewayRejectsWrongKey(t *testing.T) {
	srv, _ := makeGatewayTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set(GatewayClientHeader, "key-wrong-000")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestGatewayValidKeyForwards(t *testing.T) {
	srv, upstream := makeGatewayTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set(GatewayClientHeader, "key-laptop-456")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body %q)", rec.Code, rec.Body.String())
	}
	if upstream.receivedHeaders.Get(GatewayClientHeader) != "" {
		t.Fatal("client key header leaked to upstream")
	}
	if upstream.receivedHeaders.Get("X-Tidegate-Agent") != "" {
		t.Fatal("agent header leaked to upstream")
	}
}

// The authenticated client name overrides any spoofed X-Tidegate-Agent header.
func TestGatewayClientIdentityOverridesAgentHeader(t *testing.T) {
	srv, _ := makeGatewayTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set(GatewayClientHeader, "key-phone-123")
	req.Header.Set("X-Tidegate-Agent", "claude-code") // spoof attempt
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body %s)", rec.Code, rec.Body.String())
	}
	// The server sets X-Tidegate-Agent to the client name before the
	// router reads it; the router records it in the audit log. We can't
	// read the audit entry from here, but the override happens in
	// handleProxy — verify via the request header itself.
	if req.Header.Get("X-Tidegate-Agent") != "phone" {
		t.Fatalf("want agent=phone, got %q", req.Header.Get("X-Tidegate-Agent"))
	}
}

// Health endpoint stays open in gateway mode so monitoring doesn't need keys.
func TestGatewayHealthOpen(t *testing.T) {
	srv, _ := makeGatewayTestServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// No clients configured = legacy single-machine behavior, no auth.
func TestNoClientsMeansNoAuth(t *testing.T) {
	srv, upstream := makeTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if upstream.receivedHeaders.Get(GatewayClientHeader) != "" {
		t.Fatal("stray key header forwarded in single-machine mode")
	}
}

func TestListenAddrDefaults(t *testing.T) {
	cases := []struct {
		bind string
		port int
		want string
	}{
		{"", 8842, "127.0.0.1:8842"},
		{"localhost", 9000, "127.0.0.1:9000"},
		{"127.0.0.1", 0, "127.0.0.1:8842"},
		{"0.0.0.0", 8842, "0.0.0.0:8842"},
		{"192.168.1.50", 8842, "192.168.1.50:8842"},
		{"::1", 0, "[::1]:8842"},
	}
	for _, c := range cases {
		s := &Server{Bind: c.bind, Port: c.port}
		if got := s.listenAddr(); got != c.want {
			t.Errorf("listenAddr(bind=%q, port=%d) = %q, want %q", c.bind, c.port, got, c.want)
		}
	}
}

// A duplicate client key must not panic or misattribute. With the
// constant-time scan-all loop, the LAST matching entry deterministically
// wins (config order: project layer appends after user layer, so later
// layers override earlier ones — consistent with config precedence).
func TestGatewayDuplicateKeyLastWins(t *testing.T) {
	srv, _ := makeTestServer(t)
	srv.Clients = []Client{
		{Name: "first", Key: "shared-key"},
		{Name: "second", Key: "shared-key"},
	}
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	req.Header.Set(GatewayClientHeader, "shared-key")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if req.Header.Get("X-Tidegate-Agent") != "second" {
		t.Fatalf("want agent=second, got %q", req.Header.Get("X-Tidegate-Agent"))
	}
}

// Sanity: the gateway-mode server still redacts content before forwarding.
func TestGatewayStillRedacts(t *testing.T) {
	srv, upstream := makeGatewayTestServer(t)
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "connect to 192.168.1.77 and fetch /home/user/.env"},
	}), "openai")
	req.Header.Set(GatewayClientHeader, "key-phone-123")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := string(upstream.receivedBody)
	if strings.Contains(body, "192.168.1.77") {
		t.Fatal("private IP not redacted in gateway mode")
	}
}

// Compile-time check that route/rules imports stay used if the file evolves.
var _ = route.New
var _ = rules.BuildRuleSet

// --require-key with zero clients: everything must be rejected (lockdown).
func TestRequireKeyRejectsAllWithoutClients(t *testing.T) {
	srv, _ := makeTestServer(t)
	srv.RequireKey = true
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 in require-key mode, got %d", rec.Code)
	}
}

// handleProxy gates on len(s.Clients) > 0; RequireKey with no clients must
// also trip that gate via the Server field.
func TestHandleProxyGatesOnRequireKey(t *testing.T) {
	srv, _ := makeTestServer(t)
	srv.RequireKey = true
	req := makeChatRequest(t, makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "hello"},
	}), "openai")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// clientByKey must scan ALL clients even after a match (constant-time
// shape): with a duplicate key, the LAST match wins deterministically
// because the loop never breaks.
func TestClientByKeyScansAllClients(t *testing.T) {
	srv := &Server{Clients: []Client{
		{Name: "first", Key: "shared"},
		{Name: "second", Key: "shared"},
		{Name: "third", Key: "other"},
	}}
	c, ok := srv.clientByKey("shared")
	if !ok {
		t.Fatal("expected match")
	}
	// No early return: loop shape must be independent of match position.
	// Functional consequence: deterministic last-wins on duplicate keys.
	if c.Name != "second" {
		t.Errorf("expected last match to win, got %q", c.Name)
	}
	if _, ok := srv.clientByKey("other"); !ok {
		t.Error("expected match for trailing client")
	}
}
