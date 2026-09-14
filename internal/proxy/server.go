// Package proxy implements the Tidegate HTTP reverse proxy.
// It listens on localhost (or a LAN address in gateway mode), intercepts LLM
// API requests, routes them through the classifier/redactor/router, and
// forwards to the upstream cloud API.
//
// Local connection: plain HTTP on loopback; bind to a LAN address for
// gateway mode (pair with client keys and/or TLS).
// Upstream connection: HTTPS (TLS terminated by cloud provider).
package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qo-roj/tidegate/internal/audit"
	"github.com/qo-roj/tidegate/internal/route"
)

// UpstreamRoutes maps path prefixes to upstream API hosts.
var UpstreamRoutes = map[string]string{
	"/anthropic": "api.anthropic.com",
	"/openai":    "api.openai.com",
	"/xai":       "api.x.ai",
	"/mistral":   "api.mistral.ai",
}

// hopByHopHeaders are per-connection headers that must not be forwarded
// by a proxy, per RFC 7230 section 6.1.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// upstreamClient is the shared HTTP client for upstream API calls.
// No overall client timeout: streaming responses (SSE) can legitimately run
// for longer than any fixed deadline. Liveness is enforced at the transport
// layer instead — dial/TLS/response-header timeouts plus idle-connection
// reaping — so a dead upstream is detected quickly while live streams run
// as long as they need to.
var upstreamClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   4,
	},
}

// Server is the Tidegate proxy server.
type Server struct {
	Router   *route.Router
	AuditLog *audit.Log
	Port     int
	// Bind address. Empty or "localhost" → 127.0.0.1; "0.0.0.0" → all
	// interfaces (gateway mode). Defaults to loopback when unset.
	Bind string
	// Clients authorized in gateway mode (pre-shared keys). Empty = auth
	// disabled (single-machine mode, loopback default).
	Clients []Client
	// RequireKey rejects ALL requests when no client keys are configured
	// (--require-key lockdown mode). With clients configured this is
	// implicitly true.
	RequireKey bool
	// TLS certificate and key paths. Both set = HTTPS listener.
	CertFile string
	KeyFile  string
}

// Client is one authorized gateway client (pre-shared key).
type Client struct {
	Name string
	Key  string
}

// New creates a proxy Server.
func New(router *route.Router, auditLog *audit.Log, port int) *Server {
	return &Server{
		Router:   router,
		AuditLog: auditLog,
		Port:     port,
	}
}

// GatewayClient is the header constant carrying a gateway client's
// pre-shared key. The header is stripped before forwarding upstream.
const GatewayClientHeader = "X-Tidegate-Key"

// clientByKey resolves a pre-shared key to its client. The loop compares
// against EVERY configured key — no early return — so the number of
// comparisons (and thus request timing) is independent of which key, if
// any, matches. Early exit would let an attacker learn how far down the
// list a guessed key got (review finding: position-dependent timing).
// Duplicate keys are a config error; with them, the LAST matching entry
// wins (deterministic, and consistent with later-config-wins precedence).
func (s *Server) clientByKey(key string) (Client, bool) {
	var match Client
	found := false
	for _, c := range s.Clients {
		if subtle.ConstantTimeCompare([]byte(c.Key), []byte(key)) == 1 {
			match = c
			found = true
		}
	}
	return match, found
}

// RequireKey, when true, rejects all requests even if no client keys are
// configured (--require-key: lockdown/testing mode). authorize consults it
// via the Server field.
func (s *Server) authorize(r *http.Request) (string, bool) {
	if len(s.Clients) == 0 {
		return "", !s.RequireKey
	}
	key := r.Header.Get(GatewayClientHeader)
	if key == "" {
		return "", false
	}
	client, ok := s.clientByKey(key)
	if !ok {
		return "", false
	}
	return client.Name, true
}

// Start begins listening. Blocks until the server stops.
// The listener is created with net.Listen first, so bind errors (address
// in use, permission denied) surface immediately instead of being deferred.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.HealthCheck)
	mux.HandleFunc("/", s.handleProxy)

	addr := s.listenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	log.Printf("Tidegate proxy listening on %s", addr)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if s.CertFile != "" && s.KeyFile != "" {
		return server.ServeTLS(ln, s.CertFile, s.KeyFile)
	}
	return server.Serve(ln)
}

// listenAddr resolves the bind address to a host:port string.
// Empty, "localhost", or "loopback" → 127.0.0.1 (backward compatible).
func (s *Server) listenAddr() string {
	host := s.Bind
	switch host {
	case "", "localhost", "loopback":
		host = "127.0.0.1"
	}
	port := s.Port
	if port == 0 {
		port = 8842
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// handleProxy is the main request handler.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Gateway mode: authenticate the client via pre-shared key. The key
	// header is stripped below, so it never reaches the upstream API.
	// RequireKey (lockdown) trips the gate even with zero clients.
	if len(s.Clients) > 0 || s.RequireKey {
		clientName, ok := s.authorize(r)
		if !ok {
			log.Printf("unauthorized request from %s", r.RemoteAddr)
			http.Error(w, "unauthorized: missing or invalid "+GatewayClientHeader+" header", http.StatusUnauthorized)
			return
		}
		// The authenticated client identity is authoritative: it cannot
		// be spoofed via the X-Tidegate-Agent header.
		r.Header.Set("X-Tidegate-Agent", clientName)
	}

	// Identify the agent — check custom header first, then fall back to
	// User-Agent-based auto-detection for agents that don't set X-Tidegate-Agent.
	agent := r.Header.Get("X-Tidegate-Agent")
	if agent == "" {
		agent = detectAgent(r)
	}

	// Determine the upstream provider from the path prefix
	upstreamHost, provider := s.resolveUpstream(r.URL.Path)
	if upstreamHost == "" {
		http.Error(w, "unknown API path prefix", http.StatusBadGateway)
		return
	}

	// Read the request body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}

	// Guard against nil router (fail-closed)
	if s.Router == nil {
		http.Error(w, "gateway processing error", http.StatusBadGateway)
		return
	}

	// Process the request through the router (classify, redact, route)
	ctx, modifiedBody, blocked, err := s.Router.ProcessRequest(body, agent, provider)
	if err != nil {
		// Fail-closed: do not forward unredacted content on router error
		http.Error(w, "gateway processing error", http.StatusBadGateway)
		return
	}

	if blocked {
		// Some content was blocked — the modified body contains block messages
		// but we still forward so the agent gets a response
		log.Printf("request from agent=%s had blocked content", agent)
	}

	// Forward to upstream — strip the Tidegate path prefix, keep the query
	// string (beta features, API versions are passed there)
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/"+provider)
	if r.URL.RawQuery != "" {
		upstreamPath += "?" + r.URL.RawQuery
	}
	upstreamReq, err := http.NewRequest(r.Method, "https://"+upstreamHost+upstreamPath, strings.NewReader(string(modifiedBody)))
	if err != nil {
		http.Error(w, "creating upstream request", http.StatusInternalServerError)
		return
	}

	// Copy headers, filtering Tidegate-specific, hop-by-hop, and
	// per-connection headers per RFC 7230 section 6.1.
	for k, v := range r.Header {
		if isFilteredHeader(k) {
			continue
		}
		upstreamReq.Header[k] = v
	}
	upstreamReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))

	// Send to upstream with timeout
	resp, err := upstreamClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check if this is a streaming response (SSE)
	contentType := resp.Header.Get("Content-Type")
	isStreaming := strings.Contains(contentType, "text/event-stream")

	if isStreaming {
		s.handleStreamingResponse(w, resp, ctx)
	} else {
		s.handleBatchResponse(w, resp, ctx)
	}
}

// copyResponseHeaders copies upstream response headers to the client,
// stripping hop-by-hop headers (RFC 7230 §6.1) and the upstream
// Content-Length (the proxy may change body length during token restore,
// so the framework's own framing must be trusted instead).
func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, v := range resp.Header {
		if isHopByHop(k) || k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}
}

// isHopByHop reports whether a header is hop-by-hop per RFC 7230 §6.1.
func isHopByHop(headerName string) bool {
	for _, h := range hopByHopHeaders {
		if headerName == h {
			return true
		}
	}
	return false
}

// handleBatchResponse handles non-streaming responses.
func (s *Server) handleBatchResponse(w http.ResponseWriter, resp *http.Response, ctx *route.RequestContext) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "reading upstream response", http.StatusBadGateway)
		return
	}

	// Reverse-map tokens in the response using the per-request context
	processed := s.Router.ProcessResponse(ctx, respBody)

	copyResponseHeaders(w, resp)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(processed)))
	w.WriteHeader(resp.StatusCode)
	w.Write(processed)
}

// handleStreamingResponse handles SSE streaming responses.
// It pipes chunks through the stream redactor for token reverse-mapping.
// The StreamRedactor is created once per response to maintain the boundary
// buffer across chunks.
func (s *Server) handleStreamingResponse(w http.ResponseWriter, resp *http.Response, ctx *route.RequestContext) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback to batch mode if flushing not supported
		s.handleBatchResponse(w, resp, ctx)
		return
	}

	// Copy response headers — hop-by-hop and Content-Length stripped
	// (body length changes during token restore; the HTTP framework
	// handles framing/chunking itself).
	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Create one StreamRedactor per response — the boundary buffer
	// must persist across chunks to handle tokens split at boundaries
	sr := s.Router.NewStreamRedactor(ctx)

	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			var processed []byte
			if sr != nil {
				processed = s.Router.ProcessStreamChunk(ctx, sr, chunk)
			} else {
				processed = chunk
			}
			w.Write(processed)
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}

	// Flush any remaining buffer
	if sr != nil {
		remaining := sr.Flush()
		if len(remaining) > 0 {
			w.Write(remaining)
			flusher.Flush()
		}
	}
}

// resolveUpstream determines the upstream API host from the request path.
// Matches on path segments (not raw prefix) to prevent /anthropicevil
// matching /anthropic.
func (s *Server) resolveUpstream(path string) (host string, provider string) {
	for prefix, host := range UpstreamRoutes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return host, strings.TrimPrefix(prefix, "/")
		}
	}
	return "", ""
}

// isFilteredHeader returns true for headers that should not be forwarded
// to the upstream API: Tidegate-internal headers (agent identity and the
// gateway client key), hop-by-hop headers (RFC 7230 §6.1), and per-connection
// headers like Cookie and Host.
func isFilteredHeader(headerName string) bool {
	// Tidegate-internal
	if headerName == "X-Tidegate-Agent" || headerName == GatewayClientHeader {
		return true
	}
	// Per-connection / control headers
	if headerName == "Host" || headerName == "Content-Length" || headerName == "Cookie" {
		return true
	}
	// Hop-by-hop headers per RFC 7230
	for _, h := range hopByHopHeaders {
		if headerName == h {
			return true
		}
	}
	return false
}

// HealthCheck is a simple handler for liveness checks.
func (s *Server) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status": "ok",
		"port":   s.Port,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// agentSignatures maps User-Agent substrings to agent names. Signatures
// must be lowercase — detection compares against the lowercased User-Agent.
var agentSignatures = []struct {
	substring string
	name      string
}{
	{"claude-code", "claude-code"},
	{"claudecode", "claude-code"},
	{"anthropic-cli", "claude-code"},
	{"codex", "codex"},
	{"openai-codex", "codex"},
	{"opencode", "opencode"},
	{"hermes", "hermes"},
	{"cursor", "cursor"},
	{"aider", "aider"},
	{"cline", "cline"},
	{"continue-dev", "continue"},
	{"gh copilot", "github-copilot"},
	{"github-copilot", "github-copilot"},
	{"grok-cli", "grok-cli"},
	{"xai-cli", "grok-cli"},
}

// detectAgent identifies the calling agent from the User-Agent header.
// Returns "unknown" if no known agent signature is found.
func detectAgent(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return "unknown"
	}
	uaLower := strings.ToLower(ua)
	for _, sig := range agentSignatures {
		if strings.Contains(uaLower, sig.substring) {
			return sig.name
		}
	}
	// If we can't identify a specific agent but there's a User-Agent,
	// use a truncated version so it's distinguishable from headerless requests.
	if len(ua) > 40 {
		ua = ua[:40]
	}
	return "ua:" + ua
}
