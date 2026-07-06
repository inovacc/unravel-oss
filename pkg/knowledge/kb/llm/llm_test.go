package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseJSON(t *testing.T) {
	type payload struct {
		Foo string `json:"foo"`
		N   int    `json:"n"`
	}
	tests := []struct {
		name    string
		raw     string
		want    payload
		wantErr bool
	}{
		{
			name: "plain object",
			raw:  `{"foo":"hi","n":3}`,
			want: payload{Foo: "hi", N: 3},
		},
		{
			name: "wrapped in prose",
			raw:  "Here is the answer:\n{\"foo\":\"x\",\"n\":1}\nthanks",
			want: payload{Foo: "x", N: 1},
		},
		{
			name: "fenced json block",
			raw:  "```json\n{\"foo\":\"y\",\"n\":7}\n```",
			want: payload{Foo: "y", N: 7},
		},
		{
			name: "first of multiple objects",
			raw:  `{"foo":"a","n":1}{"foo":"b","n":2}`,
			want: payload{Foo: "a", N: 1},
		},
		{
			name: "nested braces",
			raw:  `prefix {"foo":"{nested}","n":5} suffix`,
			want: payload{Foo: "{nested}", N: 5},
		},
		{
			name:    "no object",
			raw:     `nothing here`,
			wantErr: true,
		},
		{
			name:    "unbalanced",
			raw:     `{"foo":"x"`,
			wantErr: true,
		},
		{
			name:    "malformed",
			raw:     `{"foo": not-json}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got payload
			err := ParseJSON(tt.raw, &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got value %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractFirstJSONArray(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain array", `[1,2,3]`, `[1,2,3]`},
		{"prose prefix", `here: [1,2]`, `[1,2]`},
		{"nested", `[[1,2],[3,4]]`, `[[1,2],[3,4]]`},
		{"first only", `[1,2] then [3]`, `[1,2]`},
		{"no array returns input", `hello`, `hello`},
		{"trims whitespace when no array", `  hi  `, `hi`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFirstJSONArray(tt.in)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseJSONStringEscapes(t *testing.T) {
	// A '}' inside a JSON string must not close the object.
	var v struct {
		S string `json:"s"`
	}
	if err := ParseJSON(`{"s":"a}b"}`, &v); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.S != "a}b" {
		t.Errorf("got %q, want %q", v.S, "a}b")
	}
}

// Call shells out to the `claude` CLI subprocess and is therefore not
// covered here — see TestParseJSON / TestExtractFirstJSONArray for the
// pure parsing paths the Tier-3 plan deems testable.
var _ = strings.TrimSpace

// --- sampling path tests ---

type fakeSamplingClient struct {
	body   []byte
	err    error
	called bool
}

func (f *fakeSamplingClient) Summarize(_ context.Context, _ string) ([]byte, error) {
	f.called = true
	return f.body, f.err
}

func resetSamplingResolver(t *testing.T, orig func() SamplingClient) {
	t.Helper()
	t.Cleanup(func() { samplingResolver = orig })
}

func TestCall_SamplingPathUsedWhenAvailable(t *testing.T) {
	orig := samplingResolver
	resetSamplingResolver(t, orig)

	fake := &fakeSamplingClient{body: []byte("sampling-result")}
	samplingResolver = func() SamplingClient { return fake }

	got, err := Call(context.Background(), "any-model", "prompt", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "sampling-result" {
		t.Fatalf("got %q, want sampling-result", got)
	}
	if !fake.called {
		t.Fatal("expected sampling client to be called, but it was not")
	}
}

// TestCall_SamplingErrorPropagated verifies the sampling pivot removed
// the legacy subprocess fallback: a sampling-adapter error now surfaces
// to the caller wrapped with the 'sampling:' prefix instead of being
// silently swallowed and replaced with an exec error.
func TestCall_SamplingErrorPropagated(t *testing.T) {
	orig := samplingResolver
	resetSamplingResolver(t, orig)

	fake := &fakeSamplingClient{err: errors.New("sampling unavailable")}
	samplingResolver = func() SamplingClient { return fake }

	_, err := Call(context.Background(), "any-model", "prompt", 2*time.Second)
	if err == nil {
		t.Fatal("expected error to propagate from sampling adapter")
	}
	if !fake.called {
		t.Fatal("sampling client should have been called")
	}
	if !strings.Contains(err.Error(), "sampling unavailable") {
		t.Fatalf("expected sampling adapter error to be wrapped, got: %v", err)
	}
}

// TestCall_NilResolverReturnsErrNoSamplingClient verifies that running
// without a wired sampling host returns the typed sentinel error
// (callers can errors.Is to detect this case and downgrade to a
// soft-fail).
func TestCall_NilResolverReturnsErrNoSamplingClient(t *testing.T) {
	orig := samplingResolver
	resetSamplingResolver(t, orig)

	samplingResolver = nil

	_, err := Call(context.Background(), "any-model", "prompt", 2*time.Second)
	if err == nil {
		t.Fatal("expected ErrNoSamplingClient when resolver is nil")
	}
	if !errors.Is(err, ErrNoSamplingClient) {
		t.Fatalf("expected ErrNoSamplingClient sentinel, got: %v", err)
	}
}

// TestCall_NilResolverFromFunctionReturnsErr handles the case where the
// resolver function itself is set but returns nil (e.g. session not yet
// wired) — same sentinel error path.
func TestCall_NilResolverReturnReturnsErr(t *testing.T) {
	orig := samplingResolver
	resetSamplingResolver(t, orig)

	samplingResolver = func() SamplingClient { return nil }

	_, err := Call(context.Background(), "any-model", "prompt", 2*time.Second)
	if !errors.Is(err, ErrNoSamplingClient) {
		t.Fatalf("expected ErrNoSamplingClient when resolver returns nil, got: %v", err)
	}
}
