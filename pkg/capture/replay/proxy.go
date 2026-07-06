package replay

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// Proxy serves recorded HTTP responses from a capture session.
type Proxy struct {
	responses map[string]capture.NetworkResponseData
	urls      []string
	listener  net.Listener
	server    *http.Server
	mu        sync.Mutex
}

// NewProxy creates a replay proxy from a capture session.
func NewProxy(session *capture.CaptureSession) *Proxy {
	p := &Proxy{
		responses: make(map[string]capture.NetworkResponseData),
	}

	requestURLs := make(map[string]string)
	for _, evt := range session.Events {
		if evt.Type == capture.EventNetworkRequest {
			var req capture.NetworkRequestData
			if err := json.Unmarshal(evt.Data, &req); err == nil {
				requestURLs[req.URL] = req.Method
			}
		}
	}

	for _, evt := range session.Events {
		if evt.Type != capture.EventNetworkResponse {
			continue
		}
		var resp capture.NetworkResponseData
		if err := json.Unmarshal(evt.Data, &resp); err != nil {
			continue
		}

		parsed, err := url.Parse(resp.URL)
		if err != nil {
			continue
		}

		method := "GET"
		if m, ok := requestURLs[resp.URL]; ok {
			method = m
		}

		key := fmt.Sprintf("%s %s", method, parsed.Path)
		p.responses[key] = resp
		p.urls = append(p.urls, key)
	}

	sort.Strings(p.urls)
	return p
}

// Start begins serving on a random port. Returns the address.
func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	p.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handle)
	p.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() { _ = p.server.Serve(ln) }()

	return ln.Addr().String(), nil
}

// Stop shuts down the proxy.
func (p *Proxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

// Addr returns the proxy's listen address.
func (p *Proxy) Addr() string {
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return ""
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	key := fmt.Sprintf("%s %s", r.Method, r.URL.Path)

	if resp, ok := p.responses[key]; ok {
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.Status)
		_, _ = fmt.Fprint(w, resp.Body)
		return
	}

	suggestions := p.closestMatches(r.URL.Path, 5)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)

	body := map[string]any{
		"error":       "no recorded response",
		"requested":   key,
		"suggestions": suggestions,
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (p *Proxy) closestMatches(path string, max int) []string {
	var matches []string
	for _, u := range p.urls {
		if strings.Contains(u, path) || levenshteinClose(u, path) {
			matches = append(matches, u)
			if len(matches) >= max {
				break
			}
		}
	}
	if len(matches) == 0 && len(p.urls) > 0 {
		end := min(max, len(p.urls))
		matches = p.urls[:end]
	}
	return matches
}

func levenshteinClose(a, b string) bool {
	aParts := strings.Split(a, "/")
	bParts := strings.Split(b, "/")
	shared := 0
	for _, ap := range aParts {
		for _, bp := range bParts {
			if ap == bp && ap != "" {
				shared++
				break
			}
		}
	}
	return shared > len(bParts)/2
}
