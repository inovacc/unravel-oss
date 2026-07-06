package analyze

import (
	"bytes"
	"testing"

	"github.com/andybalholm/brotli"
)

func brEnc(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecodeCacheBody_Brotli(t *testing.T) {
	js := "function wa(){return 42}=>{};addEventListener('x',()=>{})"
	got, ok := decodeCacheBody(brEnc(t, js))
	if !ok || string(got) != js {
		t.Fatalf("brotli decode failed: ok=%v got=%q", ok, got)
	}
}

func TestSniffSource(t *testing.T) {
	if k := sniffSource([]byte("self.foo=function(){};const a=>1;")); k != srcJS {
		t.Fatalf("want JS, got %v", k)
	}
	if k := sniffSource([]byte("@media screen{.x{display:flex;color:rgba(0,0,0,.5)}}")); k != srcCSS {
		t.Fatalf("want CSS, got %v", k)
	}
	if k := sniffSource([]byte{0x00, 0x01, 0x02, 0x03}); k != srcNone {
		t.Fatalf("want none, got %v", k)
	}
}

func TestRecoverProfileHTTPCacheSource_HonestEmptyNoCache(t *testing.T) {
	js, css := recoverProfileHTTPCacheSource(t.TempDir())
	if len(js) != 0 || len(css) != 0 {
		t.Fatalf("expected honest-empty, got js=%d css=%d", len(js), len(css))
	}
}
