/*
Copyright (c) 2026 Security Research
*/

package builtins

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestList_ReturnsThreeBuiltins(t *testing.T) {
	got := List()
	want := []string{"devtools", "ipc-logger", "network"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %v; want %v", got, want)
	}
}

func TestGet_AllBuiltinsHaveContent(t *testing.T) {
	for _, name := range List() {
		b, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		if len(b) == 0 {
			t.Errorf("Get(%s): empty", name)
		}
		if !strings.HasPrefix(string(b), "//") {
			t.Errorf("Get(%s): missing leading // comment header, got %q", name, string(b[:min(len(b), 20)]))
		}
	}
}

func TestHash_StableAcrossCalls(t *testing.T) {
	for _, name := range List() {
		h1, err := Hash(name)
		if err != nil {
			t.Fatalf("Hash(%s): %v", name, err)
		}
		h2, err := Hash(name)
		if err != nil {
			t.Fatalf("Hash(%s) #2: %v", name, err)
		}
		if h1 != h2 {
			t.Errorf("Hash(%s) unstable: %s vs %s", name, h1, h2)
		}
		if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
			t.Errorf("Hash(%s) bad format: %s", name, h1)
		}
	}
}

func TestGet_UnknownReturnsErr(t *testing.T) {
	_, err := Get("does-not-exist")
	if !errors.Is(err, ErrBuiltinNotFound) {
		t.Fatalf("want ErrBuiltinNotFound, got %v", err)
	}
	_, err = Hash("does-not-exist")
	if !errors.Is(err, ErrBuiltinNotFound) {
		t.Fatalf("Hash: want ErrBuiltinNotFound, got %v", err)
	}
}
