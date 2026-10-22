// Command ipscanner-forward-auth is the IPScanner forward auth gate and gating reverse proxy.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck(os.Getenv("LISTEN"), os.Getenv("HEALTH_PATH")))
		case "version", "-version", "--version":
			fmt.Println("ipscanner-forward-auth " + Version)
			return
		default:
			fmt.Fprintln(os.Stderr, "usage: ipscanner-forward-auth [healthcheck|version]; configure with environment variables")
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.LookupEnv, os.Stdout, nil); err != nil {
		os.Exit(1)
	}
}

type jsonLogger struct {
	mu  sync.Mutex
	out io.Writer
}

func (l *jsonLogger) line(raw string) {
	raw = strings.TrimSpace(raw)
	ts := `{"time":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"`
	var obj bytes.Buffer
	if strings.HasPrefix(raw, "{") && json.Compact(&obj, []byte(raw)) == nil {
		rest := obj.String()[1:]
		if rest != "}" {
			ts += ","
		}
		raw = ts + rest
	} else {
		msg, _ := json.Marshal(raw)
		raw = ts + `,"message":` + string(msg) + "}"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.out, raw+"\n")
}

type logWriter struct{ l *jsonLogger }

func (w logWriter) Write(p []byte) (int, error) {
	w.l.fields(map[string]interface{}{"level": "error", "message": strings.TrimSpace(string(p))})
	return len(p), nil
}

func (l *jsonLogger) fields(f map[string]interface{}) {
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	l.line(string(b))
}

func run(ctx context.Context, getenv func(string) (string, bool), out io.Writer, ready chan<- string) error {
	logger := &jsonLogger{out: out}
	o, err := loadOptions(getenv)
	if err != nil {
		logger.fields(map[string]interface{}{"level": "error", "message": "invalid configuration: " + err.Error()})
		return err
	}
	o.edge.Logger = logger.line
	guard, err := edge.New(o.edge)
	if err != nil {
		logger.fields(map[string]interface{}{"level": "error", "message": "invalid configuration: " + strings.TrimPrefix(err.Error(), "ipscanner: ")})
		return err
	}
	srv := &http.Server{
		Handler:           newServer(guard, o, logger.fields),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(logWriter{logger}, "", 0),
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		logger.fields(map[string]interface{}{"level": "error", "message": "listen: " + err.Error()})
		return err
	}

	mode := "forward_auth"
	upstream := ""
	if o.upstream != nil {
		mode = "proxy"
		upstream = o.upstream.Redacted()
	}
	start := map[string]interface{}{
		"level":   "info",
		"message": "ipscanner-forward-auth started",
		"version": Version,
		"listen":  ln.Addr().String(),
		"mode":    mode,
		"enabled": guard.Enabled(),
	}
	if upstream != "" {
		start["upstream"] = upstream
	}
	if site := guard.SiteID(); site != "" {
		start["site"] = site
	}
	logger.fields(start)
	if ready != nil {
		ready <- ln.Addr().String()
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		logger.fields(map[string]interface{}{"level": "error", "message": "server: " + err.Error()})
		return err
	case <-ctx.Done():
	}
	logger.fields(map[string]interface{}{"level": "info", "message": "shutting down"})
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.fields(map[string]interface{}{"level": "error", "message": "shutdown: " + err.Error()})
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// healthcheck backs the Docker HEALTHCHECK: the distroless image has no shell or curl.
func healthcheck(listen, path string) int {
	if listen == "" {
		listen = defaultListen
	}
	if path == "" {
		path = defaultHealthPath
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: invalid LISTEN")
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: "+err.Error())
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
