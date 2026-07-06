/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// maxEnvelopeBytes bounds a single newline-delimited envelope to guard
// against a malicious or buggy peer flooding the supervisor with an
// unterminated line (unbounded ReadBytes would OOM the process).
const maxEnvelopeBytes = 16 << 20 // 16 MiB

// Envelope is the JSON-RPC 2.0 wire envelope. ID == nil indicates a
// notification (no response expected). Exactly one of Result / Error
// is set in a response; neither is set in a request.
type Envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorBody      `json:"error,omitempty"`
}

// WriteEnvelope writes one envelope + newline to w. Caller serializes
// concurrent writes (codec does not lock).
func WriteEnvelope(w io.Writer, env Envelope) error {
	if env.JSONRPC == "" {
		env.JSONRPC = "2.0"
	}
	buf, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if bytes.IndexByte(buf, '\n') >= 0 {
		return fmt.Errorf("envelope contains embedded newline; framing would break")
	}
	if _, err := w.Write(append(buf, '\n')); err != nil {
		return fmt.Errorf("write envelope: %w", err)
	}
	return nil
}

// ReadEnvelope reads one newline-delimited envelope from r. Returns
// io.EOF when the underlying stream closes cleanly. The line length is
// bounded by maxEnvelopeBytes to prevent a single oversized line from
// exhausting memory; an over-budget line yields an error.
func ReadEnvelope(r *bufio.Reader) (Envelope, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxEnvelopeBytes {
			return Envelope{}, fmt.Errorf("read envelope: line exceeds %d bytes", maxEnvelopeBytes)
		}
		if err == nil {
			break // found the delimiter
		}
		if err == bufio.ErrBufferFull {
			continue // partial line; keep accumulating up to the cap
		}
		if err == io.EOF {
			if len(buf) == 0 {
				return Envelope{}, io.EOF
			}
			break // trailing line without newline
		}
		return Envelope{}, fmt.Errorf("read envelope: %w", err)
	}

	line := bytes.TrimRight(buf, "\n")
	if len(line) == 0 {
		return Envelope{}, io.EOF
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return env, nil
}
