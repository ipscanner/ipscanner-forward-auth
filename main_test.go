package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

const (
	testSite = "site_fwdauthunit000000001"
	torIP    = "185.220.101.1"
	homeIP   = "84.128.0.1"
	vpnIP    = "185.217.69.166"
	botIP    = "66.249.66.1"
	chrome   = "Mozilla/5.0 (Macintosh) Chrome/141.0.0.0 Safari/537.36"
	proxyIP  = "10.0.0.5:41000" // a proxy in the private network: trusted by default
	publicIP = "203.0.113.9:41000"
)

// fakeAPI stands in for the IPScanner API.
type fakeAPI struct {
	mu     sync.Mutex
	checks []map[string]interface{}
	heads  []http.Header
	policy string // policy JSON, "" for 404
	srv    *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func verdict(class, network string, anonymized bool) string {
	return fmt.Sprintf(`{"class":%q,"agent":{"class":"human","confidence":0.9,"action":"allow","signals":{}},"network":{"networkClass":%q,"anonymized":%t,"riskScore":10,"country":"DE"},"site":null}`, class, network, anonymized)
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	policy := f.policy
	if r.URL.Path == "/v1/edge/check" {
		f.checks = append(f.checks, body)
		f.heads = append(f.heads, r.Header.Clone())
	}
	f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/edge/check":
		switch body["ip"] {
		case torIP:
			fmt.Fprint(w, verdict("tor", "tor", true))
		case vpnIP:
			fmt.Fprint(w, verdict("vpn", "vpn", true))
		case botIP:
			fmt.Fprint(w, `{"class":"verified_bot","agent":{"class":"known_bot","confidence":0.99,"action":"allow","signals":{"allowlist_verified":true}},"network":{"networkClass":"hosting","anonymized":false,"riskScore":5,"country":"US"},"site":null}`)
		default:
			fmt.Fprint(w, verdict("human", "residential_clean", false))
		}
	case strings.HasSuffix(r.URL.Path, "/policy"):
		if policy == "" {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"unknown_site"}`)
			return
		}
		fmt.Fprint(w, policy)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeAPI) calls() []map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]interface{}(nil), f.checks...)
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func newTestServer(t *testing.T, vars map[string]string) (*server, *bytes.Buffer) {
	t.Helper()
	o, err := loadOptions(env(vars))
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	logger := &jsonLogger{out: buf}
	o.edge.Logger = logger.line
	g, err := edge.New(o.edge)
	if err != nil {
		t.Fatal(err)
	}
	return newServer(g, o, logger.fields), buf
}

func baseEnv(api *fakeAPI, extra map[string]string) map[string]string {
	vars := map[string]string{"IPSCANNER_API_KEY": "pk_test_unit", "IPSCANNER_API_URL": api.srv.URL}
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

// authRequest is a forward auth call as nginx, Traefik or Caddy make it.
func authRequest(peer, visitor, uri string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/check", nil)
	r.RemoteAddr = peer
	r.Header.Set("User-Agent", chrome)
	if visitor != "" {
		r.Header.Set("X-Forwarded-For", visitor)
	}
	if uri != "" {
		r.Header.Set("X-Forwarded-Uri", uri)
	}
	return r
}

func serve(s http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestLoadOptionsDefaults(t *testing.T) {
	o, err := loadOptions(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if o.listen != ":8080" || o.healthPath != "/healthz" || o.upstream != nil {
		t.Fatalf("defaults: %+v", o)
	}
	c := o.edge
	if c.Source != "forward_auth" || c.Client != "forward-auth" || c.Version != Version {
		t.Fatalf("identity: %+v", c)
	}
	if len(c.TrustedProxies) != 1 || c.TrustedProxies[0] != "private" {
		t.Fatalf("trusted: %v", c.TrustedProxies)
	}
	if c.SkipPaths != edge.DefaultSkipPaths || c.Timeout != edge.DefaultTimeout || c.CacheTTL != edge.DefaultCacheTTL || c.PolicyTTL != edge.DefaultPolicyTTL {
		t.Fatalf("timings: %+v", c)
	}
	if c.Mode != "" || c.SiteID != "" || c.APIKey != "" || c.Debug {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestLoadOptionsValues(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("pk_test_fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := loadOptions(env(map[string]string{
		"IPSCANNER_API_KEY":      "pk_test_env",
		"IPSCANNER_API_KEY_FILE": keyFile,
		"SITE_ID":                testSite,
		"MODE":                   "enforce",
		"BLOCK_CLASSES":          "tor, vpn",
		"TRUSTED_PROXIES":        "none",
		"IP_HEADERS":             "X-Real-IP",
		"TIMEOUT_MS":             "800",
		"CACHE_TTL":              "10m",
		"CACHE_SIZE":             "50",
		"POLICY_TTL":             "5",
		"SKIP_PATHS":             "",
		"LISTEN":                 "127.0.0.1:9000",
		"UPSTREAM_URL":           "http://app:3000",
		"DEBUG":                  "true",
		"HEALTH_PATH":            "/_health",
	}))
	if err != nil {
		t.Fatal(err)
	}
	c := o.edge
	if c.APIKey != "pk_test_fromfile" {
		t.Fatal("key file must win")
	}
	if c.TrustedProxies != nil || c.SkipPaths != edge.None || c.Timeout != 800*time.Millisecond ||
		c.CacheTTL != 10*time.Minute || c.CacheSize != 50 || c.PolicyTTL != 5*time.Second || !c.Debug {
		t.Fatalf("parsed: %+v", c)
	}
	if o.upstream.String() != "http://app:3000" || o.listen != "127.0.0.1:9000" || o.healthPath != "/_health" {
		t.Fatalf("server: %+v", o)
	}
	if _, err := edge.New(c); err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]string{
		"TIMEOUT_MS":             "fast",
		"CACHE_TTL":              "-1",
		"POLICY_TTL":             "soon",
		"CACHE_SIZE":             "0",
		"DEBUG":                  "maybe",
		"UPSTREAM_URL":           "ftp://x",
		"LISTEN":                 "8080",
		"HEALTH_PATH":            "healthz",
		"IPSCANNER_API_KEY_FILE": filepath.Join(dir, "missing"),
	} {
		if _, err := loadOptions(env(map[string]string{name: value})); err == nil {
			t.Errorf("%s=%q: expected an error", name, value)
		}
	}
}

func TestCheckAllowsResidentialWithHeaders(t *testing.T) {
	api := newFakeAPI(t)
	s, _ := newTestServer(t, baseEnv(api, nil))
	r := authRequest(proxyIP, homeIP, "/account?x=1")
	r.Header.Set("Accept-Language", "de")
	w := serve(s, r)
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	h := w.Header()
	if h.Get("X-IPScanner-Status") != "ok" || h.Get("X-IPScanner-Class") != "human" || h.Get("X-IPScanner-Action") != "allow" ||
		h.Get("X-IPScanner-Network-Class") != "residential_clean" || h.Get("X-IPScanner-Country") != "DE" {
		t.Fatalf("headers %v", h)
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Fatal("allow must not be cached by the proxy")
	}
	calls := api.calls()
	if len(calls) != 1 || calls[0]["ip"] != homeIP || calls[0]["user_agent"] != chrome {
		t.Fatalf("calls %v", calls)
	}
	if hs, _ := calls[0]["headers"].(map[string]interface{}); hs["accept-language"] != "de" {
		t.Fatalf("signal headers %v", calls[0]["headers"])
	}
	hd := api.heads[0]
	if hd.Get("X-IPScanner-Source") != "forward_auth" || hd.Get("User-Agent") != "ipscanner-forward-auth/"+Version ||
		hd.Get("Authorization") != "Bearer pk_test_unit" {
		t.Fatalf("api headers %v", hd)
	}
}

func TestCheckBlocksConfiguredClassInEnforce(t *testing.T) {
	api := newFakeAPI(t)
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"MODE": "enforce", "BLOCK_CLASSES": "tor"}))
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Code != 403 {
		t.Fatalf("code %d", w.Code)
	}
	id := w.Header().Get("X-IPScanner-Request-Id")
	if id == "" || !strings.Contains(w.Body.String(), id) || !strings.Contains(w.Body.String(), "Access denied") {
		t.Fatalf("block page %q id %q", w.Body.String(), id)
	}
	if w.Header().Get("X-IPScanner-Action") != "block" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", w.Header())
	}
	// A bot on a VPN counts as vpn without a site, like the WordPress plugin.
	s2, _ := newTestServer(t, baseEnv(api, map[string]string{"MODE": "enforce", "BLOCK_CLASSES": "tor"}))
	if w := serve(s2, authRequest(proxyIP, vpnIP, "/")); w.Code != 200 {
		t.Fatalf("vpn not in BLOCK_CLASSES: %d", w.Code)
	}
}

func TestCheckMonitorNeverBlocks(t *testing.T) {
	api := newFakeAPI(t)
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"BLOCK_CLASSES": "tor"}))
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Action") != "would_block" {
		t.Fatalf("code %d headers %v", w.Code, w.Header())
	}
}

func TestCheckSitePolicy(t *testing.T) {
	api := newFakeAPI(t)
	api.policy = `{"mode":"enforce","policy":{"tor":"block","vpn":"flag"},"version":3}`
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"SITE_ID": testSite}))

	if w := serve(s, authRequest(proxyIP, torIP, "/")); w.Code != 403 {
		t.Fatalf("tor: %d", w.Code)
	}
	w := serve(s, authRequest(proxyIP, vpnIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Action") != "flag" || w.Header().Get("X-IPScanner-Site") != testSite {
		t.Fatalf("vpn: %d %v", w.Code, w.Header())
	}
	r := authRequest(proxyIP, botIP, "/")
	r.Header.Set("User-Agent", "Googlebot/2.1")
	if w := serve(s, r); w.Code != 200 || w.Header().Get("X-IPScanner-Class") != "verified_bot" {
		t.Fatalf("verified bot: %d %v", w.Code, w.Header())
	}
	if c := api.calls(); c[0]["site"] != testSite {
		t.Fatalf("site not sent: %v", c[0])
	}

	// MODE=monitor keeps a site in monitor mode whatever the dashboard says.
	m, _ := newTestServer(t, baseEnv(api, map[string]string{"SITE_ID": testSite, "MODE": "monitor"}))
	if w := serve(m, authRequest(proxyIP, torIP, "/")); w.Code != 200 || w.Header().Get("X-IPScanner-Action") != "would_block" {
		t.Fatalf("monitor override: %d %v", w.Code, w.Header())
	}
}

func TestCheckCachesVerdict(t *testing.T) {
	api := newFakeAPI(t)
	s, _ := newTestServer(t, baseEnv(api, nil))
	for i := 0; i < 3; i++ {
		if w := serve(s, authRequest(proxyIP, homeIP, "/")); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if n := len(api.calls()); n != 1 {
		t.Fatalf("calls %d, want 1", n)
	}
	r := authRequest(proxyIP, homeIP, "/")
	r.Header.Set("User-Agent", "other")
	serve(s, r)
	if n := len(api.calls()); n != 2 {
		t.Fatalf("another user agent is another visitor: %d calls", n)
	}
}

func TestUntrustedPeerHeadersIgnored(t *testing.T) {
	api := newFakeAPI(t)
	s, logs := newTestServer(t, baseEnv(api, map[string]string{"MODE": "enforce", "BLOCK_CLASSES": "tor"}))
	// A public peer is not a trusted proxy: the spoofed X-Forwarded-For
	// and the X-Forwarded-Uri are ignored, the peer itself is checked.
	w := serve(s, authRequest(publicIP, torIP, "/logo.png"))
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	calls := api.calls()
	if len(calls) != 1 || calls[0]["ip"] != "203.0.113.9" {
		t.Fatalf("calls %v", calls)
	}
	if !strings.Contains(logs.String(), "outside TRUSTED_PROXIES") {
		t.Fatalf("missing warning: %s", logs.String())
	}

	// TRUSTED_PROXIES=none: even a private peer is not trusted.
	n, _ := newTestServer(t, baseEnv(api, map[string]string{"MODE": "enforce", "BLOCK_CLASSES": "tor", "TRUSTED_PROXIES": "none"}))
	w = serve(n, authRequest(proxyIP, torIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("none: %d %v", w.Code, w.Header())
	}
}

func TestTrustedPeerMethodAndURI(t *testing.T) {
	api := newFakeAPI(t)
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"MODE": "enforce", "BLOCK_CLASSES": "tor"}))
	if w := serve(s, authRequest(proxyIP, torIP, "/assets/app.css?v=2")); w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("static asset: %d %v", w.Code, w.Header())
	}
	r := authRequest(proxyIP, torIP, "")
	r.Header.Set("X-Original-URI", "/robots.txt")
	if w := serve(s, r); w.Header().Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("nginx X-Original-URI: %v", w.Header())
	}
	r = authRequest(proxyIP, torIP, "/api")
	r.Header.Set("X-Forwarded-Method", "OPTIONS")
	if w := serve(s, r); w.Header().Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("OPTIONS: %v", w.Header())
	}
	if n := len(api.calls()); n != 0 {
		t.Fatalf("skipped requests called the API %d times", n)
	}
	if w := serve(s, authRequest(proxyIP, torIP, "/login")); w.Code != 403 {
		t.Fatalf("page: %d", w.Code)
	}
}

func TestFailOpen(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	s, _ := newTestServer(t, map[string]string{
		"IPSCANNER_API_KEY": "pk_test_unit", "IPSCANNER_API_URL": url,
		"MODE": "enforce", "BLOCK_CLASSES": "tor",
	})
	start := time.Now()
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "error" {
		t.Fatalf("code %d %v", w.Code, w.Header())
	}
	w = serve(s, authRequest(proxyIP, homeIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "backoff" {
		t.Fatalf("backoff: %d %v", w.Code, w.Header())
	}
	if time.Since(start) > time.Second {
		t.Fatalf("fail open took %s", time.Since(start))
	}
	h := serve(s, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body healthBody
	if err := json.Unmarshal(h.Body.Bytes(), &body); err != nil || h.Code != 200 || !body.Backoff || body.LastError != "error" {
		t.Fatalf("health: %d %s", h.Code, h.Body.String())
	}
}

func TestFailOpenTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	s, _ := newTestServer(t, map[string]string{
		"IPSCANNER_API_KEY": "pk_test_unit", "IPSCANNER_API_URL": slow.URL, "TIMEOUT_MS": "100",
	})
	start := time.Now()
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "timeout" {
		t.Fatalf("code %d %v", w.Code, w.Header())
	}
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Fatalf("timeout took %s", d)
	}
}

func TestNoKeyPassesThrough(t *testing.T) {
	s, logs := newTestServer(t, nil)
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Code != 200 || w.Header().Get("X-IPScanner-Status") != "skipped" {
		t.Fatalf("code %d %v", w.Code, w.Header())
	}
	if !strings.Contains(logs.String(), "no API key") {
		t.Fatalf("logs %s", logs.String())
	}
}

func TestDebugHeaders(t *testing.T) {
	api := newFakeAPI(t)
	s, logs := newTestServer(t, baseEnv(api, map[string]string{"DEBUG": "1"}))
	w := serve(s, authRequest(proxyIP, torIP, "/"))
	if w.Header().Get("X-IPScanner-Class") != "tor" {
		t.Fatalf("headers %v", w.Header())
	}
	if !strings.Contains(logs.String(), `"trafficClass":"tor"`) {
		t.Fatalf("decision log missing: %s", logs.String())
	}
}

func TestBlockedPage(t *testing.T) {
	s, _ := newTestServer(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	r.Header.Set("X-IPScanner-Request-Id", "abc-123")
	w := serve(s, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "abc-123") || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
	}
	w = serve(s, httptest.NewRequest(http.MethodGet, "/blocked?id=%3Cscript%3E", nil))
	if w.Code != 403 || strings.Contains(w.Body.String(), "script") || strings.Contains(w.Body.String(), "Request ID") {
		t.Fatalf("invalid id must be dropped: %s", w.Body.String())
	}
	if w := serve(s, httptest.NewRequest(http.MethodGet, "/other", nil)); w.Code != 404 {
		t.Fatalf("unknown path: %d", w.Code)
	}
}

func TestHealth(t *testing.T) {
	api := newFakeAPI(t)
	api.policy = `{"mode":"enforce","policy":{"tor":"block"},"version":7}`
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"SITE_ID": testSite}))
	serve(s, authRequest(proxyIP, homeIP, "/"))
	w := serve(s, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var b healthBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || b.Status != "ok" || b.Version != Version || b.Mode != "forward_auth" || !b.Enabled ||
		b.Site != testSite || b.PolicyMode != "enforce" || b.PolicyVersion != 7 || b.CachedVerdicts != 1 || b.Backoff {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

type upstreamSeen struct {
	mu      sync.Mutex
	headers http.Header
	host    string
	path    string
	hits    int
}

func newUpstream(t *testing.T) (*httptest.Server, *upstreamSeen) {
	seen := &upstreamSeen{}
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.headers, seen.host, seen.path = r.Header.Clone(), r.Host, r.URL.RequestURI()
		seen.hits++
		seen.mu.Unlock()
		fmt.Fprint(w, "app")
	}))
	t.Cleanup(u.Close)
	return u, seen
}

func TestProxyMode(t *testing.T) {
	api := newFakeAPI(t)
	up, seen := newUpstream(t)
	s, _ := newTestServer(t, baseEnv(api, map[string]string{"UPSTREAM_URL": up.URL, "MODE": "enforce", "BLOCK_CLASSES": "tor"}))

	r := httptest.NewRequest(http.MethodGet, "http://shop.example/cart?x=1", nil)
	r.RemoteAddr = proxyIP
	r.Header.Set("User-Agent", chrome)
	r.Header.Set("X-Forwarded-For", homeIP)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-IPScanner-Class", "verified_bot") // spoofed verdict
	w := serve(s, r)
	if w.Code != 200 || w.Body.String() != "app" {
		t.Fatalf("code %d body %q", w.Code, w.Body.String())
	}
	h := seen.headers
	if h.Get("X-IPScanner-Class") != "human" || h.Get("X-IPScanner-Status") != "ok" || h.Get("X-IPScanner-Action") != "allow" {
		t.Fatalf("upstream headers %v", h)
	}
	if seen.host != "shop.example" || seen.path != "/cart?x=1" {
		t.Fatalf("host %q path %q", seen.host, seen.path)
	}
	if h.Get("X-Forwarded-For") != homeIP+", 10.0.0.5" || h.Get("X-Forwarded-Proto") != "https" || h.Get("X-Forwarded-Host") != "shop.example" {
		t.Fatalf("forwarded %v", h)
	}
	if w.Header().Get("X-IPScanner-Class") != "" {
		t.Fatal("debug headers on the response without DEBUG")
	}

	r = httptest.NewRequest(http.MethodGet, "http://shop.example/", nil)
	r.RemoteAddr = proxyIP
	r.Header.Set("X-Forwarded-For", torIP)
	w = serve(s, r)
	if w.Code != 403 || seen.hits != 1 || !strings.Contains(w.Body.String(), "Access denied") {
		t.Fatalf("blocked: %d hits %d", w.Code, seen.hits)
	}

	// From an untrusted peer the forwarded headers are replaced.
	r = httptest.NewRequest(http.MethodGet, "http://shop.example/", nil)
	r.RemoteAddr = publicIP
	r.Header.Set("X-Forwarded-For", torIP)
	r.Header.Set("X-Forwarded-Proto", "https")
	w = serve(s, r)
	if w.Code != 200 || seen.headers.Get("X-Forwarded-For") != "203.0.113.9" || seen.headers.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("untrusted: %d %v", w.Code, seen.headers)
	}

	// The health path is answered by the gate, everything else goes on.
	if w := serve(s, httptest.NewRequest(http.MethodGet, "/healthz", nil)); !strings.Contains(w.Body.String(), `"mode":"proxy"`) {
		t.Fatalf("health %s", w.Body.String())
	}
	before := seen.hits
	r = httptest.NewRequest(http.MethodGet, "/check", nil)
	r.RemoteAddr = proxyIP
	serve(s, r)
	if seen.hits != before+1 {
		t.Fatal("/check must be proxied in proxy mode")
	}
}

func TestProxyUpstreamDown(t *testing.T) {
	api := newFakeAPI(t)
	up := httptest.NewServer(http.NotFoundHandler())
	url := up.URL
	up.Close()
	s, logs := newTestServer(t, baseEnv(api, map[string]string{"UPSTREAM_URL": url}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = proxyIP
	r.Header.Set("X-Forwarded-For", homeIP)
	if w := serve(s, r); w.Code != 502 {
		t.Fatalf("code %d", w.Code)
	}
	if !strings.Contains(logs.String(), "upstream request failed") {
		t.Fatalf("logs %s", logs.String())
	}
}

func TestRunAndShutdown(t *testing.T) {
	api := newFakeAPI(t)
	vars := baseEnv(api, map[string]string{"LISTEN": "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(vars), out, ready) }()
	addr := <-ready

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health %d", resp.StatusCode)
	}
	if code := healthcheck(addr, ""); code != 0 {
		t.Fatalf("healthcheck exit %d", code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no graceful shutdown")
	}
	if code := healthcheck(addr, ""); code == 0 {
		t.Fatal("healthcheck must fail when the server is down")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, line := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["time"] == nil {
			t.Fatalf("not a JSON log line: %q", line)
		}
	}
	if !strings.Contains(out.String(), "started") || !strings.Contains(out.String(), "shutting down") || strings.Contains(out.String(), "pk_test_unit") {
		t.Fatalf("logs %s", out.String())
	}
}

func TestRunInvalidConfig(t *testing.T) {
	out := &syncBuffer{}
	err := run(context.Background(), env(map[string]string{"MODE": "block"}), out, nil)
	if err == nil || !strings.Contains(out.String(), "invalid configuration") {
		t.Fatalf("err %v logs %s", err, out.String())
	}
}

func TestJSONLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	l := &jsonLogger{out: buf}
	l.line(`{"a":1}`)
	l.line("plain text")
	l.line("{}")
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["time"] == nil {
			t.Fatalf("line %q", line)
		}
	}
}

func TestURIPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b?c=d":               "/a/b",
		"/x.css#top":             "/x.css",
		"https://ex.com/p?q":     "/p",
		"relative":               "/relative",
		"/%E2%9C%93/robots.txt?": "/✓/robots.txt",
	} {
		if got := uriPath(in); got != want {
			t.Errorf("uriPath(%q) = %q, want %q", in, got, want)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
