package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

// Paths of the forward auth endpoints.
const (
	checkPath   = "/check"
	blockedPath = "/blocked"
)

// requestIDHeader carries the request ID of a blocked check, so a proxy
// that shows its own 403 page (nginx error_page) can pass it to /blocked.
const requestIDHeader = "X-IPScanner-Request-Id"

// server is the HTTP handler: forward auth endpoints, or a reverse proxy
// in front of UPSTREAM_URL.
type server struct {
	guard      *edge.Guard
	healthPath string
	upstream   *url.URL
	proxy      *httputil.ReverseProxy
	log        func(fields map[string]interface{})
	warnOnce   sync.Once
}

func newServer(g *edge.Guard, o options, log func(map[string]interface{})) *server {
	s := &server{guard: g, healthPath: o.healthPath, upstream: o.upstream, log: log}
	if o.upstream != nil {
		s.proxy = s.newProxy(o.upstream)
	}
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == s.healthPath {
		s.health(w, r)
		return
	}
	if s.proxy != nil {
		if _, ok := s.guard.Handle(w, r); !ok {
			return
		}
		s.proxy.ServeHTTP(w, r)
		return
	}
	switch r.URL.Path {
	case checkPath:
		s.check(w, r)
	case blockedPath:
		s.blocked(w, r)
	default:
		http.NotFound(w, r)
	}
}

// check is the forward auth endpoint: 200 with X-IPScanner-* headers to
// allow, 403 with the block page to block. The original method and URI
// come from the proxy's headers, believed only from a trusted proxy.
func (s *server) check(w http.ResponseWriter, r *http.Request) {
	ip := s.guard.ClientIP(r)
	v := edge.VisitorFrom(r, ip)
	if s.guard.TrustedPeer(r) {
		if m := firstHeader(r.Header, "X-Forwarded-Method", "X-Original-Method"); m != "" {
			v.Method = m
		}
		if u := firstHeader(r.Header, "X-Forwarded-Uri", "X-Original-Uri", "X-Original-Url"); u != "" {
			v.Path = uriPath(u)
		}
	} else {
		s.warnOnce.Do(func() {
			s.log(map[string]interface{}{
				"level":   "warn",
				"message": "forward auth request from a peer outside TRUSTED_PROXIES: its IP and URI headers are ignored",
				"peer":    r.RemoteAddr,
			})
		})
	}

	d := s.guard.CheckVisitor(r.Context(), v)
	h := w.Header()
	for name, value := range d.Headers() {
		h.Set(name, value)
	}
	if s.guard.Debug() {
		for name, value := range d.DebugHeaders() {
			h.Set(name, value)
		}
	}
	if d.Blocked() {
		if d.RequestID != "" {
			h.Set(requestIDHeader, d.RequestID)
		}
		s.guard.WriteBlocked(w, d)
		return
	}
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// blocked serves the 403 page for proxies that cannot pass the body of
// the auth response on (nginx auth_request). The request ID comes from the
// X-IPScanner-Request-Id header or the id query parameter.
func (s *server) blocked(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(requestIDHeader)
	if id == "" {
		id = r.URL.Query().Get("id")
	}
	if !validRequestID(id) {
		id = ""
	}
	s.guard.WriteBlocked(w, edge.Decision{RequestID: id})
}

type healthBody struct {
	Status         string `json:"status"`
	Version        string `json:"version"`
	Mode           string `json:"mode"`
	Enabled        bool   `json:"enabled"`
	Site           string `json:"site,omitempty"`
	Backoff        bool   `json:"backoff"`
	BackoffUntil   string `json:"backoffUntil,omitempty"`
	LastError      string `json:"lastError,omitempty"`
	LastErrorAt    string `json:"lastErrorAt,omitempty"`
	PolicyMode     string `json:"policyMode,omitempty"`
	PolicyVersion  int    `json:"policyVersion,omitempty"`
	CachedVerdicts int    `json:"cachedVerdicts"`
}

// health always answers 200: the gate fails open, so an unreachable API
// does not make it unhealthy. The body says what the guard is doing.
func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	st := s.guard.State()
	b := healthBody{
		Status:         "ok",
		Version:        Version,
		Mode:           "forward_auth",
		Enabled:        st.Enabled,
		Site:           st.SiteID,
		Backoff:        !st.BackoffUntil.IsZero(),
		CachedVerdicts: st.CachedVerdicts,
	}
	if s.proxy != nil {
		b.Mode = "proxy"
	}
	if b.Backoff {
		b.BackoffUntil = st.BackoffUntil.UTC().Format(time.RFC3339)
	}
	if !st.LastErrorAt.IsZero() {
		b.LastError = st.LastStatus
		b.LastErrorAt = st.LastErrorAt.UTC().Format(time.RFC3339)
	}
	if st.Policy != nil {
		b.PolicyMode = st.Policy.Mode
		b.PolicyVersion = st.Policy.Version
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(b)
}

// newProxy forwards allowed requests to the upstream. The Host header is
// kept. X-Forwarded-For gets the peer appended; X-Forwarded-* from a
// trusted proxy are kept, from anyone else replaced.
func (s *server) newProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			trusted := s.guard.TrustedPeer(pr.In)
			peer, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				peer = pr.In.RemoteAddr
			}
			xff := peer
			if trusted {
				if prior := strings.Join(pr.In.Header.Values("X-Forwarded-For"), ", "); prior != "" {
					xff = prior + ", " + peer
				}
			}
			pr.Out.Header.Set("X-Forwarded-For", xff)
			host, proto := "", ""
			if trusted {
				host = pr.In.Header.Get("X-Forwarded-Host")
				proto = pr.In.Header.Get("X-Forwarded-Proto")
			}
			if host == "" {
				host = pr.In.Host
			}
			if proto == "" {
				proto = "http"
				if pr.In.TLS != nil {
					proto = "https"
				}
			}
			pr.Out.Header.Set("X-Forwarded-Host", host)
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log(map[string]interface{}{"level": "error", "message": "upstream request failed", "error": err.Error(), "path": r.URL.Path})
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

func firstHeader(h http.Header, names ...string) string {
	for _, name := range names {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return v
		}
	}
	return ""
}

// uriPath returns the path of a request URI such as /a/b?c=d.
func uriPath(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	if u, err := url.Parse(uri); err == nil && u.Path != "" {
		uri = u.Path
	}
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return uri
}

func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
