package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

func FuzzLoadOptions(f *testing.F) {
	f.Add(":8080", "/healthz", "private", "", "1500", "600", "30s", "10000", "true", "", "enforce", "tor,vpn", "site_abc", "X-Real-IP")
	f.Add("127.0.0.1:9000", "/", "none", "", "0", "-1", "soon", "-5", "maybe", "ftp://x", "block", "human", "abc", "")
	f.Add("8080", "healthz", "10.0.0.0/8, cloudflare", "(", "99999999999999999999", "1h", "1ns", "1", "off", "http://app:3000", "monitor", "none", "", "CF-Connecting-IP")
	f.Fuzz(func(t *testing.T, listen, health, trusted, skip, timeout, cacheTTL, policyTTL, cacheSize, debug, upstream, mode, classes, site, headers string) {
		vars := map[string]string{
			"IPSCANNER_API_KEY": "pk_test_fuzz", "IPSCANNER_API_URL": "http://127.0.0.1:1",
			"LISTEN": listen, "HEALTH_PATH": health, "TRUSTED_PROXIES": trusted, "SKIP_PATHS": skip,
			"TIMEOUT_MS": timeout, "CACHE_TTL": cacheTTL, "POLICY_TTL": policyTTL, "CACHE_SIZE": cacheSize,
			"DEBUG": debug, "UPSTREAM_URL": upstream, "MODE": mode, "BLOCK_CLASSES": classes,
			"SITE_ID": site, "IP_HEADERS": headers,
		}
		o, err := loadOptions(env(vars))
		if err != nil {
			return
		}
		if _, _, err := net.SplitHostPort(o.listen); err != nil {
			t.Fatalf("LISTEN %q accepted", o.listen)
		}
		if !strings.HasPrefix(o.healthPath, "/") {
			t.Fatalf("HEALTH_PATH %q accepted", o.healthPath)
		}
		if o.edge.Timeout <= 0 || o.edge.CacheTTL <= 0 || o.edge.PolicyTTL <= 0 || o.edge.CacheSize <= 0 {
			t.Fatalf("non-positive limits accepted: %+v", o.edge)
		}
		if o.upstream != nil && (o.upstream.Host == "" || (o.upstream.Scheme != "http" && o.upstream.Scheme != "https")) {
			t.Fatalf("UPSTREAM_URL %q accepted", o.upstream)
		}
		o.edge.Logger = func(string) {}
		g, err := edge.New(o.edge)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "ipscanner: ") {
				t.Fatalf("error %q", err)
			}
			return
		}
		newServer(g, o, func(map[string]interface{}) {})
	})
}

type fuzzAPI struct {
	mu     sync.Mutex
	checks int
	lastIP string
}

func (a *fuzzAPI) serve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	a.mu.Lock()
	a.checks++
	a.lastIP = body.IP
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch body.IP {
	case torIP:
		fmt.Fprint(w, verdict("tor", "tor", true))
	default:
		fmt.Fprint(w, verdict("human", "residential_clean", false))
	}
}

func (a *fuzzAPI) last() (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checks, a.lastIP
}

func fuzzServer(f *testing.F, extra map[string]string) (*server, *fuzzAPI) {
	api := &fuzzAPI{}
	srv := httptest.NewServer(http.HandlerFunc(api.serve))
	f.Cleanup(srv.Close)
	vars := map[string]string{"IPSCANNER_API_KEY": "pk_test_fuzz", "IPSCANNER_API_URL": srv.URL, "MODE": "enforce", "BLOCK_CLASSES": "tor"}
	for k, v := range extra {
		vars[k] = v
	}
	o, err := loadOptions(env(vars))
	if err != nil {
		f.Fatal(err)
	}
	o.edge.Logger = func(string) {}
	g, err := edge.New(o.edge)
	if err != nil {
		f.Fatal(err)
	}
	return newServer(g, o, func(map[string]interface{}) {}), api
}

// FuzzCheck checks that a peer outside TRUSTED_PROXIES cannot choose the checked IP, path or method.
func FuzzCheck(f *testing.F) {
	s, api := fuzzServer(f, nil)
	f.Add(publicIP, torIP, "/logo.png", "OPTIONS", chrome)
	f.Add(proxyIP, torIP, "/login", "GET", chrome)
	f.Add(proxyIP, "1.2.3.4, "+homeIP, "/app.css?v=1", "", chrome)
	f.Add("[2001:db8::1]:443", "10.0.0.1", "//evil.example/x.js", "options", "")
	f.Add(torIP+":1", homeIP, "/robots.txt", "HEAD", "curl/8")
	f.Add("[::ffff:10.0.0.5]:1", torIP+":5555", "relative/path", "POST", chrome)
	f.Fuzz(func(t *testing.T, peer, xff, uri, method, ua string) {
		host, _, err := net.SplitHostPort(peer)
		if err != nil || net.ParseIP(host) == nil {
			return
		}
		r := httptest.NewRequest(http.MethodGet, "/check", nil)
		r.RemoteAddr = peer
		r.Header.Set("User-Agent", ua)
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Forwarded-Uri", uri)
		r.Header.Set("X-Original-Url", uri)
		r.Header.Set("X-Forwarded-Method", method)
		trusted := s.guard.TrustedPeer(r)
		peerIP := edgeIP(host)
		before, _ := api.last()

		w := serve(s, r)

		status := w.Header().Get("X-IPScanner-Status")
		if status == "" || (w.Code != http.StatusOK && w.Code != http.StatusForbidden) {
			t.Fatalf("code %d status %q", w.Code, status)
		}
		if w.Code == http.StatusForbidden && !validRequestID(w.Header().Get(requestIDHeader)) {
			t.Fatalf("block without a valid request ID: %q", w.Header().Get(requestIDHeader))
		}
		if trusted {
			return
		}
		if after, ip := api.last(); after != before && ip != peerIP {
			t.Fatalf("untrusted peer %s: checked %q", peer, ip)
		}
		if isPublicIP(peerIP) && status == edge.StatusSkipped {
			t.Fatalf("untrusted public peer %s skipped the check with uri %q method %q", peer, uri, method)
		}
	})
}

func edgeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsInterfaceLocalMulticast()
}

func FuzzBlocked(f *testing.F) {
	s, _ := fuzzServer(f, nil)
	ref := serve(s, httptest.NewRequest(http.MethodGet, "/blocked?id=x", nil)).Body.String()
	bare := serve(s, httptest.NewRequest(http.MethodGet, "/blocked", nil)).Body.String()
	f.Add("abc-123", true)
	f.Add("<script>alert(1)</script>", false)
	f.Add(`"><img src=x>`, true)
	f.Add(strings.Repeat("a", 65), false)
	f.Fuzz(func(t *testing.T, id string, viaHeader bool) {
		r := httptest.NewRequest(http.MethodGet, "/blocked", nil)
		if viaHeader {
			r.Header.Set(requestIDHeader, id)
		} else {
			r.URL.RawQuery = url.Values{"id": {id}}.Encode()
		}
		w := serve(s, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("code %d", w.Code)
		}
		body := w.Body.String()
		want := bare
		if validRequestID(id) {
			want = ref
		}
		for _, c := range []string{"<", ">", `"`, "'"} {
			if strings.Count(body, c) != strings.Count(want, c) {
				t.Fatalf("request ID %q changed the markup: %s", id, body)
			}
		}
	})
}

// FuzzProxyRewrite checks the X-Forwarded-* headers the gating proxy sends upstream.
func FuzzProxyRewrite(f *testing.F) {
	s, _ := fuzzServer(f, map[string]string{"UPSTREAM_URL": "http://app:3000"})
	target, _ := url.Parse("http://app:3000")
	rp := s.newProxy(target)
	f.Add(publicIP, torIP, "evil.example", "https", "shop.example")
	f.Add(proxyIP, homeIP, "shop.example", "https", "shop.example")
	f.Add(proxyIP, "", "", "", "shop.example:8443")
	f.Add("[2001:db8::1]:443", "1.1.1.1, 2.2.2.2", "x", "gopher", "")
	f.Fuzz(func(t *testing.T, peer, xff, xfh, xfp, host string) {
		peerHost, _, err := net.SplitHostPort(peer)
		if err != nil || net.ParseIP(peerHost) == nil {
			return
		}
		in := httptest.NewRequest(http.MethodGet, "http://shop.example/cart", nil)
		in.Host = host
		in.RemoteAddr = peer
		in.Header.Set("X-Forwarded-For", xff)
		in.Header.Set("X-Forwarded-Host", xfh)
		in.Header.Set("X-Forwarded-Proto", xfp)
		pr := &httputil.ProxyRequest{In: in, Out: in.Clone(context.Background())}
		rp.Rewrite(pr)

		out := pr.Out
		if out.URL.Host != target.Host || out.URL.Scheme != target.Scheme || out.Host != in.Host {
			t.Fatalf("target %s host %q", out.URL, out.Host)
		}
		gotXFF := out.Header.Get("X-Forwarded-For")
		if !strings.HasSuffix(gotXFF, peerHost) {
			t.Fatalf("X-Forwarded-For %q does not end with the peer %s", gotXFF, peerHost)
		}
		if s.guard.TrustedPeer(in) {
			return
		}
		if gotXFF != peerHost || out.Header.Get("X-Forwarded-Host") != in.Host {
			t.Fatalf("untrusted peer %s: X-Forwarded-For %q Host %q", peer, gotXFF, out.Header.Get("X-Forwarded-Host"))
		}
		if p := out.Header.Get("X-Forwarded-Proto"); p != "http" && p != "https" {
			t.Fatalf("untrusted peer chose X-Forwarded-Proto %q", p)
		}
	})
}

func FuzzJSONLogger(f *testing.F) {
	f.Add(`{"a":1}`)
	f.Add(`{}`)
	f.Add("plain text")
	f.Add(`{"ipscanner":"upstream failure","status":"error","code":0}`)
	f.Add("  {\"a\":\n1}  ")
	f.Add(`{ }`)
	f.Add(`{oops}`)
	f.Fuzz(func(t *testing.T, raw string) {
		buf := &bytes.Buffer{}
		l := &jsonLogger{out: buf}
		l.line(raw)
		out := buf.String()
		if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
			t.Fatalf("not one line: %q", out)
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("line(%q) wrote invalid JSON %q: %v", raw, out, err)
		}
		if _, ok := m["time"]; !ok {
			t.Fatalf("no time in %q", out)
		}
		var in map[string]interface{}
		if json.Unmarshal([]byte(raw), &in) == nil && in != nil {
			for k := range in {
				if _, ok := m[k]; !ok {
					t.Fatalf("field %q lost: %q", k, out)
				}
			}
		} else if utf8.ValidString(raw) && m["message"] != strings.TrimSpace(raw) {
			t.Fatalf("message %q, want %q", m["message"], strings.TrimSpace(raw))
		}
	})
}
