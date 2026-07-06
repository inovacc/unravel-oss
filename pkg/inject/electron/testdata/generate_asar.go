//go:build ignore

// generate_asar.go produces preload-fixture.asar containing a minimal main.js
// + preload.js. Run with: go run ./testdata/generate_asar.go
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type fileEntry struct {
	Offset string                `json:"offset,omitempty"`
	Size   int64                 `json:"size,omitempty"`
	Files  map[string]*fileEntry `json:"files,omitempty"`
}

type header struct {
	Files map[string]*fileEntry `json:"files"`
}

func main() {
	mainJS := []byte(`const { BrowserWindow } = require('electron');
const path = require('path');
new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
    preload: 'preload.js'
  }
});
`)
	preloadJS := []byte(`window.addEventListener('DOMContentLoaded', () => {});
`)

	var data []byte
	mainOff := int64(len(data))
	data = append(data, mainJS...)
	preloadOff := int64(len(data))
	data = append(data, preloadJS...)

	hdr := header{
		Files: map[string]*fileEntry{
			"main.js":    {Offset: fmt.Sprintf("%d", mainOff), Size: int64(len(mainJS))},
			"preload.js": {Offset: fmt.Sprintf("%d", preloadOff), Size: int64(len(preloadJS))},
		},
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		panic(err)
	}

	// Pad header to 4-byte alignment.
	padLen := (4 - (len(hdrJSON) % 4)) % 4
	padded := make([]byte, len(hdrJSON)+padLen)
	copy(padded, hdrJSON)
	for i := len(hdrJSON); i < len(padded); i++ {
		padded[i] = ' '
	}

	// Pickle layout: 16-byte prefix + JSON + (padding) + data.
	// prefix = [4]uint32:
	//   [0] = 4 (size of next field)
	//   [1] = headerSize (8 + len(padded))  -> total bytes from offset 8 onward of header section
	//   [2] = headerSize - 4
	//   [3] = len(hdrJSON)  (string size)
	prefix := make([]byte, 16)
	headerSize := uint32(8 + len(padded))
	binary.LittleEndian.PutUint32(prefix[0:4], 4)
	binary.LittleEndian.PutUint32(prefix[4:8], headerSize)
	binary.LittleEndian.PutUint32(prefix[8:12], headerSize-4)
	binary.LittleEndian.PutUint32(prefix[12:16], uint32(len(hdrJSON)))

	out := filepath.Join(filepath.Dir(os.Args[0]), "preload-fixture.asar")
	if cwd, _ := os.Getwd(); cwd != "" {
		out = filepath.Join(cwd, "preload-fixture.asar")
	}
	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(prefix); err != nil {
		panic(err)
	}
	if _, err := f.Write(padded); err != nil {
		panic(err)
	}
	if _, err := f.Write(data); err != nil {
		panic(err)
	}
	fmt.Println("wrote", out, "bytes:", 16+len(padded)+len(data))
}
