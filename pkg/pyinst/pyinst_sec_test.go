package pyinst

import (
	"testing"
)

// TestCookie20_NegativePkgLen verifies that a negative int32 pkgLen is rejected.
func TestCookie20_NegativePkgLen(t *testing.T) {
	// pkgLen=-1, tocLen=1 (valid), tocOff=0, pyver=0
	cookie := buildCookie20(int32(-1), 0, 1, 0)
	data := make([]byte, 512)

	result := &PyInstBinary{CookiePos: 0}
	ok := parseCookie20(cookie, result, data)
	if ok {
		t.Fatal("expected parseCookie20 to return false for negative pkgLen, got true")
	}
}

// TestCookie20_PkgLenExceedsData verifies that pkgLen > len(data) is rejected.
func TestCookie20_PkgLenExceedsData(t *testing.T) {
	data := make([]byte, 256)
	cookie := buildCookie20(int32(len(data)+1), 0, 1, 0)

	result := &PyInstBinary{CookiePos: 0}
	ok := parseCookie20(cookie, result, data)
	if ok {
		t.Fatal("expected parseCookie20 to return false for pkgLen > len(data), got true")
	}
}

// TestCookie21_ZeroPkgLen verifies that pkgLen==0 is rejected.
func TestCookie21_ZeroPkgLen(t *testing.T) {
	cookie := buildCookie21(0, 0, 1, 0, "libpython3.11.so.1.0")
	data := make([]byte, 512)

	result := &PyInstBinary{CookiePos: 0}
	ok := parseCookie21(cookie, result, data)
	if ok {
		t.Fatal("expected parseCookie21 to return false for pkgLen=0, got true")
	}
}

// TestCookie21_PkgLenExceedsData verifies that pkgLen > len(data) is rejected.
func TestCookie21_PkgLenExceedsData(t *testing.T) {
	data := make([]byte, 256)
	cookie := buildCookie21(uint32(len(data)+1), 0, 1, 0, "libpython3.11.so.1.0")

	result := &PyInstBinary{CookiePos: 0}
	ok := parseCookie21(cookie, result, data)
	if ok {
		t.Fatal("expected parseCookie21 to return false for pkgLen > len(data), got true")
	}
}
