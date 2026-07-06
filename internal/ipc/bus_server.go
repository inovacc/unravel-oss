/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// handshakeTimeout bounds how long the server waits for a peer to send the
// sys.hello frame before dropping the connection. A var so tests can shrink
// it. Generous by default so a slow legitimate client is never penalised.
var handshakeTimeout = 10 * time.Second

// Server runs an accept loop on a net.Listener and dispatches each verb
// call to the registered HandlerFunc. Per-connection goroutine.
type Server struct {
	verbs        map[string]HandlerFunc
	verbsMu      sync.RWMutex
	logger       *slog.Logger
	token        string       // "" ⇒ auth disabled (unit tests over net.Pipe)
	peerVerifier PeerVerifier // nil ⇒ skip peer-cred

	// Lifecycle: handlerWG tracks every in-flight dispatch goroutine so
	// Shutdown can drain them before the owner (supervisor) closes the DB
	// pool. draining gates new dispatches once shutdown begins.
	handlerWG    sync.WaitGroup
	draining     atomic.Bool
	lastActivity atomic.Int64 // unix-nano of the most recent inbound envelope
}

// SetAuth enables hard authentication: every connection must pass the
// peer-credential check (if verifier != nil) AND present token as the first
// (sys.hello) message before any verb is dispatched.
//
// SetAuth must be called once during setup, before Serve/ServeConn starts
// accepting connections; token and verifier are read without locking.
func (s *Server) SetAuth(token string, verifier PeerVerifier) {
	s.token = token
	s.peerVerifier = verifier
}

// NewServer returns a Server with no verbs registered.
func NewServer() *Server {
	return &Server{
		verbs:  make(map[string]HandlerFunc),
		logger: slog.Default(),
	}
}

// RegisterVerb adds a handler for method. Overwrites any existing handler
// for the same method.
func (s *Server) RegisterVerb(method string, h HandlerFunc) {
	s.verbsMu.Lock()
	defer s.verbsMu.Unlock()
	s.verbs[method] = h
}

// HasVerb reports whether method has a registered handler.
func (s *Server) HasVerb(method string) bool {
	s.verbsMu.RLock()
	defer s.verbsMu.RUnlock()
	_, ok := s.verbs[method]
	return ok
}

// Serve accepts connections until ln.Accept() returns an error (typically
// ln.Close()). Returns the accept error.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(ctx, conn)
	}
}

// ServeConn reads envelopes from conn and dispatches each as a verb call.
// When auth is enabled (SetAuth called), the connection must pass a peer-
// credential check and a valid sys.hello handshake before any verb runs.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Per-connection context: cancelled when this connection's read loop ends
	// (client disconnect / EOF / read error). Handlers receive connCtx, so a
	// dropped client aborts that connection's in-flight DB queries / CDP
	// captures instead of running to completion against the server-lifetime ctx.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r := bufio.NewReader(conn)
	var writeMu sync.Mutex

	var peer PeerInfo
	if s.token != "" {
		p, ok := s.authenticate(connCtx, conn, r, &writeMu)
		if !ok {
			return // authenticate already logged + responded
		}
		peer = p
	}
	s.verbLoop(connCtx, conn, r, &writeMu, peer)
}

// authenticate runs the peer-cred check and the mandatory sys.hello handshake.
// Returns true only if the connection is authenticated.
//
// SECURITY SCOPE: this raises the bar (a peer must read the 0600 token file,
// not merely reach the socket) and yields an audit trail. It is NOT a
// containment boundary against a fully-privileged same-user attacker, who can
// read the token file or attach to this process. See spec
// docs/superpowers/specs/2026-05-29-supervisor-ipc-peer-auth-design.md section 6.
func (s *Server) authenticate(ctx context.Context, conn net.Conn, r *bufio.Reader, mu *sync.Mutex) (PeerInfo, bool) {
	var peer PeerInfo
	if s.peerVerifier != nil {
		p, err := s.peerVerifier(conn)
		if err != nil {
			s.logger.Warn("ipc auth: peer-cred rejected", "reason", "wrong-uid", "err", err)
			return PeerInfo{}, false
		}
		peer = p
	}

	// Bound the hello read: a peer that connects but never sends sys.hello must
	// not pin this goroutine + fd forever. ReadEnvelope does not consult ctx, so
	// a wall-clock deadline on the conn is the enforcement mechanism.
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	env, err := ReadEnvelope(r)
	if err != nil {
		s.logger.Warn("ipc auth: read hello failed", "peer_pid", peer.PID, "err", err)
		return PeerInfo{}, false
	}
	if env.Method != MethodHello {
		s.logger.Warn("ipc auth: verb before hello", "reason", "verb-before-hello", "method", env.Method, "peer_pid", peer.PID)
		s.respondError(conn, mu, env.ID, &ErrorBody{Code: CodeUnauthorized, Message: "handshake required"})
		return PeerInfo{}, false
	}
	var hello HelloRequest
	if err := json.Unmarshal(env.Params, &hello); err != nil {
		s.logger.Warn("ipc auth: bad hello params", "reason", "bad-token", "peer_pid", peer.PID, "err", err)
		s.respondError(conn, mu, env.ID, &ErrorBody{Code: CodeUnauthorized, Message: "invalid hello"})
		return PeerInfo{}, false
	}
	if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(s.token)) != 1 {
		s.logger.Warn("ipc auth: token rejected", "reason", "bad-token", "peer_uid", peer.UID, "peer_pid", peer.PID)
		s.respondError(conn, mu, env.ID, &ErrorBody{Code: CodeUnauthorized, Message: "invalid token"})
		return PeerInfo{}, false
	}
	// Clear the handshake deadline: an authenticated connection may legitimately
	// sit idle between verbs, and we must not kill it mid-session.
	_ = conn.SetReadDeadline(time.Time{})
	s.replyHello(conn, mu, env.ID, peer)
	s.logger.Info("ipc auth: connection authenticated", "peer_uid", peer.UID, "peer_pid", peer.PID)
	return peer, true
}

// replyHello writes a HelloResponse for id. Used for the initial handshake and
// for an idempotent re-affirm when an already-authenticated client sends
// sys.hello again.
func (s *Server) replyHello(conn net.Conn, mu *sync.Mutex, id *int64, peer PeerInfo) {
	hr := HelloResponse{ServerVersion: "1", ServerUID: peer.UID, ProtocolVersion: ProtocolVersion}
	buf, _ := json.Marshal(hr)
	mu.Lock()
	_ = WriteEnvelope(conn, Envelope{ID: id, Result: json.RawMessage(buf)})
	mu.Unlock()
}

// verbLoop is the original ServeConn read/dispatch loop, factored out so the
// handshake can consume the first envelope and pass the same reader here. When
// auth is enabled, a repeated sys.hello is answered idempotently (a fresh
// HelloResponse) rather than dispatched as an unknown verb.
func (s *Server) verbLoop(ctx context.Context, conn net.Conn, r *bufio.Reader, writeMu *sync.Mutex, peer PeerInfo) {
	for {
		env, err := ReadEnvelope(r)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			s.logger.Warn("bus_server: read envelope failed", "err", err)
			return
		}
		s.lastActivity.Store(time.Now().UnixNano())
		if s.token != "" && env.Method == MethodHello {
			s.replyHello(conn, writeMu, env.ID, peer)
			continue
		}
		// Refuse new work once draining so a verb cannot start against an
		// owner that is tearing down the DB pool (#4/#6/#17).
		if s.draining.Load() {
			if env.ID != nil {
				s.respondError(conn, writeMu, env.ID, &ErrorBody{
					Code: CodeUnavailable, Message: "supervisor is shutting down",
				})
			}
			continue
		}
		// Track the dispatch goroutine so Shutdown can drain it. Add before the
		// go statement; Done in dispatch's defer. Re-check draining after Add to
		// avoid the Add-after-Shutdown-Wait race.
		s.handlerWG.Add(1)
		if s.draining.Load() {
			s.handlerWG.Done()
			if env.ID != nil {
				s.respondError(conn, writeMu, env.ID, &ErrorBody{
					Code: CodeUnavailable, Message: "supervisor is shutting down",
				})
			}
			continue
		}
		go s.dispatch(ctx, conn, writeMu, env)
	}
}

func (s *Server) dispatch(ctx context.Context, w io.Writer, mu *sync.Mutex, req Envelope) {
	defer s.handlerWG.Done()
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("bus_server: handler panic", "method", req.Method, "panic", r)
			if req.ID != nil {
				s.respondError(w, mu, req.ID, &ErrorBody{
					Code: CodeInternal, Message: fmt.Sprintf("handler panic: %v", r),
				})
			}
		}
	}()

	s.verbsMu.RLock()
	h, ok := s.verbs[req.Method]
	s.verbsMu.RUnlock()

	if !ok {
		if req.ID != nil {
			s.respondError(w, mu, req.ID, &ErrorBody{
				Code: CodeNotFound, Message: "method not registered: " + req.Method,
			})
		}
		return
	}

	result, errBody := h(ctx, req.Params)
	if req.ID == nil {
		// notification — no response
		return
	}
	if errBody != nil {
		s.respondError(w, mu, req.ID, errBody)
		return
	}

	buf, err := json.Marshal(result)
	if err != nil {
		s.respondError(w, mu, req.ID, &ErrorBody{
			Code: CodeInternal, Message: "marshal result: " + err.Error(),
		})
		return
	}

	resp := Envelope{ID: req.ID, Result: json.RawMessage(buf)}
	mu.Lock()
	_ = WriteEnvelope(w, resp)
	mu.Unlock()
}

func (s *Server) respondError(w io.Writer, mu *sync.Mutex, id *int64, body *ErrorBody) {
	resp := Envelope{ID: id, Error: body}
	mu.Lock()
	_ = WriteEnvelope(w, resp)
	mu.Unlock()
}

// Shutdown stops accepting new verb dispatches and drains in-flight handler
// goroutines, returning once they finish or ctx expires (bounded drain — a
// wedged handler must not block shutdown forever). The owner (supervisor)
// calls this BEFORE closing the DB pool so handlers never touch a closed
// pool. New verbs arriving on still-open connections are answered with
// CodeUnavailable. Safe to call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	done := make(chan struct{})
	go func() {
		s.handlerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("ipc: shutdown drain timed out: %w", ctx.Err())
	}
}

// Draining reports whether Shutdown has begun and not yet finished draining the
// in-flight dispatch goroutines. Lets callers gate idle-exit on quiescence.
func (s *Server) Draining() bool { return s.draining.Load() }

// LastActivity returns the time of the most recent inbound envelope, or the
// zero time if none has arrived. Used by the supervisor's idle watcher.
func (s *Server) LastActivity() time.Time {
	ns := s.lastActivity.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
