package main

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

const Version = "0.1.0"

const (
	source            = "forward_auth"
	client            = "forward-auth"
	defaultListen     = ":8080"
	defaultHealthPath = "/healthz"
	defaultTrusted    = "private"
)

type options struct {
	edge       edge.Config
	listen     string
	upstream   *url.URL
	healthPath string
}

func loadOptions(getenv func(string) (string, bool)) (options, error) {
	get := func(name string) string {
		v, _ := getenv(name)
		return strings.TrimSpace(v)
	}
	o := options{
		listen:     get("LISTEN"),
		healthPath: get("HEALTH_PATH"),
	}
	if o.listen == "" {
		o.listen = defaultListen
	}
	if _, _, err := net.SplitHostPort(o.listen); err != nil {
		return o, errors.New("LISTEN must look like :8080 or 127.0.0.1:8080")
	}
	if o.healthPath == "" {
		o.healthPath = defaultHealthPath
	}
	if !strings.HasPrefix(o.healthPath, "/") {
		return o, errors.New("HEALTH_PATH must start with /")
	}

	key := get("IPSCANNER_API_KEY")
	if file := get("IPSCANNER_API_KEY_FILE"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return o, errors.New("IPSCANNER_API_KEY_FILE: " + err.Error())
		}
		key = strings.TrimSpace(string(raw))
	}

	trusted := defaultTrusted
	if v, ok := getenv("TRUSTED_PROXIES"); ok {
		trusted = strings.TrimSpace(v)
	}
	if strings.EqualFold(trusted, edge.None) {
		trusted = ""
	}

	// SKIP_PATHS unset skips static assets; set but empty checks every path.
	skip := edge.DefaultSkipPaths
	if v, ok := getenv("SKIP_PATHS"); ok {
		skip = strings.TrimSpace(v)
		if skip == "" {
			skip = edge.None
		}
	}

	timeout, err := millis(get("TIMEOUT_MS"), edge.DefaultTimeout, "TIMEOUT_MS")
	if err != nil {
		return o, err
	}
	cacheTTL, err := seconds(get("CACHE_TTL"), edge.DefaultCacheTTL, "CACHE_TTL")
	if err != nil {
		return o, err
	}
	policyTTL, err := seconds(get("POLICY_TTL"), edge.DefaultPolicyTTL, "POLICY_TTL")
	if err != nil {
		return o, err
	}
	cacheSize := edge.DefaultCacheSize
	if v := get("CACHE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return o, errors.New("CACHE_SIZE must be a positive number")
		}
		cacheSize = n
	}
	debug, err := boolean(get("DEBUG"), "DEBUG")
	if err != nil {
		return o, err
	}

	if v := get("UPSTREAM_URL"); v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return o, errors.New("UPSTREAM_URL must be an http or https URL")
		}
		o.upstream = u
	}

	o.edge = edge.Config{
		APIKey:         key,
		APIURL:         get("IPSCANNER_API_URL"),
		SiteID:         get("SITE_ID"),
		Mode:           get("MODE"),
		BlockClasses:   list(get("BLOCK_CLASSES")),
		TrustedProxies: list(trusted),
		IPHeaders:      list(get("IP_HEADERS")),
		Timeout:        timeout,
		CacheTTL:       cacheTTL,
		CacheSize:      cacheSize,
		PolicyTTL:      policyTTL,
		SkipPaths:      skip,
		Source:         source,
		Client:         client,
		Version:        Version,
		BlockMessage:   get("BLOCK_MESSAGE"),
		Debug:          debug,
	}
	return o, nil
}

func list(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

func millis(v string, fallback time.Duration, name string) (time.Duration, error) {
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, errors.New(name + " must be a positive number of milliseconds")
	}
	return time.Duration(n) * time.Millisecond, nil
}

func seconds(v string, fallback time.Duration, name string) (time.Duration, error) {
	if v == "" {
		return fallback, nil
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second, nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d, nil
	}
	return 0, errors.New(name + " must be a positive number of seconds or a duration such as 10m")
}

func boolean(v, name string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	}
	return false, errors.New(name + " must be true or false")
}
