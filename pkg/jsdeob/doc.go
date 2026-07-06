/*
Copyright (c) 2026 Security Research
*/

// Package jsdeob deobfuscates and analyzes JavaScript code.
//
// It unpacks packed scripts, decodes hex/unicode/base64/charcode strings,
// simplifies constant math expressions, renames mangled variables, beautifies
// minified code, and extracts URLs, function names, and API calls.
//
// Entry points:
//   - Deobfuscate: run the full deobfuscation pipeline with configurable options
//   - Beautify: format minified JavaScript with proper indentation
//   - DecodeStrings: decode hex, unicode, base64, and charcode encoded strings
//   - UnpackPacked: unpack function(p,a,c,k,e,d) style packers
//   - ExtractURLs: extract URLs from JavaScript source
//   - ExtractAPICalls: extract fetch/axios/XMLHttpRequest calls
package jsdeob
