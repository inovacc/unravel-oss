/*
Copyright (c) 2026 Security Research
*/

package overlay

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// Source is the provenance label for a merged node.
type Source string

const (
	SourceStatic Source = "static"
	SourceLive   Source = "live"
	SourceBoth   Source = "both"
)

// Annotation holds the provenance metadata attached to every leaf in a
// merged tree. Used as the documented shape; the merge engine emits
// raw map[string]any values matching this layout for JSON friendliness.
type Annotation struct {
	Source      Source `json:"_source"`
	CaptureTS   string `json:"_capture_ts"`
	StaticValue any    `json:"_static_value,omitempty"`
}

// Options configures Merge.
type Options struct {
	StaticTS time.Time // capture timestamp for the static pass
	LiveTS   time.Time // capture timestamp for the live pass
}

// Merge combines two arbitrary JSON-shaped trees and returns a single
// annotated tree. Inputs MUST be JSON-shaped: map[string]any, []any, or
// scalar (string, float64, bool, nil) — i.e., the output of
// json.Unmarshal into any.
//
// Per D-08: live wins on conflict; the original static scalar/array is
// archived in the leaf's _static_value field. Per D-12: inputs are not
// mutated; a fresh tree is returned.
func Merge(static, live any, opts Options) any {
	sTS := isoUTC(opts.StaticTS)
	lTS := isoUTC(opts.LiveTS)
	return mergeNode(static, live, sTS, lTS)
}

// MergeJSON marshals/unmarshals typed values into the generic JSON
// shape, then merges, returning the merged top-level map. If the merge
// produces a non-map root (rare — only when both inputs are scalars or
// arrays at the top), the value is wrapped under a "_root" key for
// stable downstream serialization.
func MergeJSON(staticV, liveV any, opts Options) (map[string]any, error) {
	sNode, err := toNode(staticV)
	if err != nil {
		return nil, fmt.Errorf("static toNode: %w", err)
	}
	lNode, err := toNode(liveV)
	if err != nil {
		return nil, fmt.Errorf("live toNode: %w", err)
	}
	out := Merge(sNode, lNode, opts)
	if m, ok := out.(map[string]any); ok {
		return m, nil
	}
	return map[string]any{"_root": out}, nil
}

func toNode(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func isoUTC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// mergeNode dispatches by the type pair (s, l).
func mergeNode(s, l any, sTS, lTS string) any {
	sNil := s == nil
	lNil := l == nil
	switch {
	case sNil && lNil:
		return annotated(nil, SourceBoth, lTS, nil)
	case sNil && !lNil:
		return walkAnnotate(l, SourceLive, lTS)
	case !sNil && lNil:
		return walkAnnotate(s, SourceStatic, sTS)
	}
	// Both non-nil: dispatch by shape.
	sm, sIsMap := s.(map[string]any)
	lm, lIsMap := l.(map[string]any)
	if sIsMap && lIsMap {
		return mergeMaps(sm, lm, sTS, lTS)
	}
	sa, sIsArr := s.([]any)
	la, lIsArr := l.([]any)
	if sIsArr && lIsArr {
		return mergeArrays(sa, la, sTS, lTS)
	}
	// Scalar / type-mismatch leaves.
	return mergeLeaf(s, l, sTS, lTS)
}

func mergeMaps(s, l map[string]any, sTS, lTS string) map[string]any {
	out := make(map[string]any, len(s)+len(l))
	for k, sv := range s {
		if lv, ok := l[k]; ok {
			out[k] = mergeNode(sv, lv, sTS, lTS)
		} else {
			out[k] = walkAnnotate(sv, SourceStatic, sTS)
		}
	}
	for k, lv := range l {
		if _, ok := s[k]; !ok {
			out[k] = walkAnnotate(lv, SourceLive, lTS)
		}
	}
	return out
}

func mergeArrays(s, l []any, sTS, lTS string) any {
	if reflect.DeepEqual(s, l) {
		return annotated(walkArr(l, SourceBoth, lTS), SourceBoth, lTS, nil)
	}
	return annotated(walkArr(l, SourceLive, lTS), SourceLive, lTS, s)
}

func mergeLeaf(s, l any, sTS, lTS string) any {
	if reflect.DeepEqual(s, l) {
		return annotated(l, SourceBoth, lTS, nil)
	}
	return annotated(l, SourceLive, lTS, s)
}

// annotated builds the standard provenance leaf. _static_value is
// included only when staticVal is non-nil (D-08 conflict archive).
func annotated(value any, src Source, ts string, staticVal any) map[string]any {
	out := map[string]any{
		"_value":      value,
		"_source":     string(src),
		"_capture_ts": ts,
	}
	if staticVal != nil {
		out["_static_value"] = staticVal
	}
	return out
}

// walkAnnotate annotates an entire single-source subtree.
func walkAnnotate(v any, src Source, ts string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = walkAnnotate(vv, src, ts)
		}
		return out
	case []any:
		return annotated(walkArr(x, src, ts), src, ts, nil)
	default:
		return annotated(x, src, ts, nil)
	}
}

func walkArr(a []any, src Source, ts string) []any {
	out := make([]any, len(a))
	for i, e := range a {
		out[i] = walkAnnotate(e, src, ts)
	}
	return out
}
