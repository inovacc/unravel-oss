/*
Copyright (c) 2026 Security Research
*/

// Package embed scans PE binaries for XAML/XBF resources stored in
// RT_RCDATA. It is the "PE-embedded" tier of FRM-06: catches unpackaged
// WinUI 3 single-file deploys that ship UI markup inside the executable.
package embed

// RT_RCDATA is the Windows resource type ID for raw application data
// (winuser.h #define RT_RCDATA MAKEINTRESOURCE(10)).
const RT_RCDATA uint32 = 10

// XBFMagic is the 4-byte magic prefix of a Microsoft.UI.Xaml binary XAML
// resource. Decoder lives in plan 04 (pkg/winui/xaml/xbf).
var XBFMagic = []byte{'X', 'B', 'F', 0x00}

// XMLProloguePrefixes is the set of byte prefixes treated as "this RT_RCDATA
// blob is plain-text XAML". These cover the real-world prologues observed in
// unpackaged WinUI 3 builds.
var XMLProloguePrefixes = [][]byte{
	[]byte("<?xml"),
	[]byte("<Page "),
	[]byte("<Page\r"),
	[]byte("<Page\n"),
	[]byte("<Application "),
	[]byte("<UserControl "),
	[]byte("<Window "),
	[]byte("<ResourceDictionary "),
}
