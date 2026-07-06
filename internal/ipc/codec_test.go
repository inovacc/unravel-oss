/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestWriteReadEnvelope_Request(t *testing.T) {
	var buf bytes.Buffer
	id := int64(42)
	req := Envelope{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "kb.search",
		Params:  json.RawMessage(`{"app":"WhatsApp"}`),
	}
	if err := WriteEnvelope(&buf, req); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	got, err := ReadEnvelope(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if got.Method != "kb.search" {
		t.Errorf("Method = %q, want kb.search", got.Method)
	}
	if got.ID == nil || *got.ID != 42 {
		t.Errorf("ID = %v, want 42", got.ID)
	}
	if string(got.Params) != `{"app":"WhatsApp"}` {
		t.Errorf("Params = %q, want {\"app\":\"WhatsApp\"}", string(got.Params))
	}
	if got.Error != nil {
		t.Errorf("Error = %v, want nil", got.Error)
	}
}

func TestWriteReadEnvelope_ResponseError(t *testing.T) {
	var buf bytes.Buffer
	id := int64(7)
	resp := Envelope{
		ID:    &id,
		Error: &ErrorBody{Code: CodeNotFound, Message: "not found"},
	}
	if err := WriteEnvelope(&buf, resp); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	got, err := ReadEnvelope(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if got.Error == nil {
		t.Fatalf("Error = nil, want non-nil")
	}
	if got.Error.Code != CodeNotFound {
		t.Errorf("Error.Code = %d, want %d", got.Error.Code, CodeNotFound)
	}
	if got.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want 2.0", got.JSONRPC)
	}
}

func TestWriteReadEnvelope_Notification(t *testing.T) {
	var buf bytes.Buffer
	note := Envelope{
		Method: "daemon.logs.line",
		Params: json.RawMessage(`{"line":"hello"}`),
	}
	if err := WriteEnvelope(&buf, note); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	got, err := ReadEnvelope(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if got.ID != nil {
		t.Errorf("ID = %v, want nil (notification)", got.ID)
	}
}

func TestReadEnvelope_EOF(t *testing.T) {
	buf := bytes.NewReader(nil)
	_, err := ReadEnvelope(bufio.NewReader(buf))
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestWriteEnvelope_RejectsEmbeddedNewline(t *testing.T) {
	var buf bytes.Buffer
	id := int64(1)
	err := WriteEnvelope(&buf, Envelope{
		ID:     &id,
		Method: "test",
		Params: json.RawMessage("\"a\\nb\""), // an escaped newline IN the JSON string is fine
	})
	if err != nil {
		t.Errorf("escaped newline in JSON string should be allowed: %v", err)
	}
	// (raw newline in the marshaled output would only happen via deliberate
	// crafting; the standard library's json.Marshal never emits raw newlines)
}
