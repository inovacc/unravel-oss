/* Copyright (c) 2026 Security Research */
package leveldb

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatSummary(t *testing.T) {
	result := &ParseResult{
		SourcePath:  "/tmp/test/leveldb",
		ParsedAt:    "2026-01-01T00:00:00Z",
		StorageType: "localStorage",
		Entries:     []Entry{{Key: "test", Value: "value", Type: "value"}},
		ByOrigin: map[string][]Entry{
			"https://example.com": {{Key: "test", Value: "value", Type: "value"}},
		},
		Stats: ParseStats{
			TotalEntries:   10,
			ValidEntries:   8,
			DeletedEntries: 2,
			ParseErrors:    0,
			LogFiles:       1,
			LDBFiles:       3,
		},
	}

	got := FormatSummary(result)

	expected := []string{
		"LevelDB Parse Summary",
		"/tmp/test/leveldb",
		"localStorage",
		"Total Entries: 10",
		"Valid Entries: 8",
		"Deleted Entries: 2",
		"Log Files Parsed: 1",
		"LDB Files Parsed: 3",
		"https://example.com",
	}

	for _, want := range expected {
		if !strings.Contains(got, want) {
			t.Errorf("FormatSummary() missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestParseDirectoryNonExistent(t *testing.T) {
	_, err := ParseDirectory("/tmp/nonexistent-leveldb-path-12345")
	if err == nil {
		t.Fatal("ParseDirectory() expected error for non-existent path, got nil")
	}
}

func TestParseDirectory_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	if result.Stats.TotalEntries != 0 {
		t.Errorf("expected 0 entries, got %d", result.Stats.TotalEntries)
	}
}

func TestParseDirectory_StorageTypeDetection(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want string
	}{
		{"localStorage", "local", "localStorage"},
		{"sessionStorage", "session", "sessionStorage"},
		{"indexedDB", "indexeddb", "indexedDB"},
		{"unknown", "random", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			dir := filepath.Join(tmpDir, tt.dir)

			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			result, err := ParseDirectory(dir)
			if err != nil {
				t.Fatalf("ParseDirectory: %v", err)
			}

			if result.StorageType != tt.want {
				t.Errorf("StorageType = %q, want %q", result.StorageType, tt.want)
			}
		})
	}
}

func TestParseLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "000001.log")

	// Build a minimal LevelDB log file with one record
	record := buildLogRecord(t)

	if err := os.WriteFile(logFile, record, 0o644); err != nil {
		t.Fatal(err)
	}

	result := &ParseResult{
		ByOrigin: make(map[string][]Entry),
	}

	ParseLogFile(logFile, result)

	// ParseLogFile should not panic and should add entries or errors
	// (Stats.LogFiles is only incremented by parseDir, not ParseLogFile directly)
	if len(result.Errors) > 0 {
		t.Logf("ParseLogFile errors (may be expected): %v", result.Errors)
	}
}

func TestParseLDBFile(t *testing.T) {
	tmpDir := t.TempDir()
	ldbFile := filepath.Join(tmpDir, "000001.ldb")

	// Write some data with embedded strings
	data := []byte("some binary data with https://example.com and key=value pairs\x00more data")
	if err := os.WriteFile(ldbFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result := &ParseResult{
		ByOrigin: make(map[string][]Entry),
	}

	ParseLDBFile(ldbFile, result)

	// Just ensure no panic; Stats.LDBFiles is only incremented by parseDir
	t.Logf("LDB parse: entries=%d errors=%d", len(result.Entries), len(result.Errors))
}

func TestParseDirectory_WithLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	// Name it "local" so storage type detection works
	dbDir := filepath.Join(tmpDir, "local")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}

	logFile := filepath.Join(dbDir, "000001.log")
	record := buildLogRecord(t)

	if err := os.WriteFile(logFile, record, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ParseDirectory(dbDir)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	if result.Stats.LogFiles == 0 {
		t.Error("expected at least 1 log file parsed")
	}

	if result.StorageType != "localStorage" {
		t.Errorf("expected localStorage, got %q", result.StorageType)
	}
}

func TestOrganizeByOrigin(t *testing.T) {
	result := &ParseResult{
		Entries: []Entry{
			{Key: "k1", Value: "v1", Origin: "https://example.com"},
			{Key: "k2", Value: "v2", Origin: "https://example.com"},
			{Key: "k3", Value: "v3", Origin: "https://other.com"},
		},
		ByOrigin: make(map[string][]Entry),
	}

	organizeByOrigin(result)

	if len(result.ByOrigin["https://example.com"]) != 2 {
		t.Errorf("expected 2 entries for example.com, got %d", len(result.ByOrigin["https://example.com"]))
	}

	if len(result.ByOrigin["https://other.com"]) != 1 {
		t.Errorf("expected 1 entry for other.com, got %d", len(result.ByOrigin["https://other.com"]))
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple ascii",
			input: []byte{'h', 0, 'i', 0},
			want:  "hi",
		},
		{
			name:  "empty",
			input: nil,
			want:  "",
		},
		{
			name:  "odd length returns empty",
			input: []byte{'h', 0, 'i'},
			want:  "", // odd length fails the len%2 check, returns empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeUTF16LE(tt.input)
			if got != tt.want {
				t.Errorf("decodeUTF16LE(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ascii text", "hello world", true},
		{"with newlines", "line1\nline2", true},
		{"with tabs", "col1\tcol2", true},
		{"empty", "", true},
		{"binary data", string([]byte{0x00, 0x01, 0x02}), false},
		{"mixed", "hello\x00world", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintable(tt.s)
			if got != tt.want {
				t.Errorf("isPrintable(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestParseChromiumKey(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		wantOrigin string
		wantKey    string
	}{
		{
			name:       "origin with null separator and odd-length storage key",
			key:        []byte("_https://example.com\x00key"),
			wantOrigin: "https://example.com",
			wantKey:    "https://example.com :: key",
		},
		{
			name:       "origin without leading underscore",
			key:        []byte("https://example.com\x00mykey"),
			wantOrigin: "https://example.com",
			wantKey:    "https://example.com :: mykey",
		},
		{
			name:       "no null separator odd-length key",
			key:        []byte("_abc"),
			wantOrigin: "",
			wantKey:    "abc",
		},
		{
			name:       "empty key",
			key:        []byte{},
			wantOrigin: "",
			wantKey:    "",
		},
		{
			name:       "null at start falls to else branch",
			key:        []byte("_\x00v"),
			wantOrigin: "",
			wantKey:    "\u7600", // nullIdx==0, else branch; UTF-8 has null (non-printable), UTF-16LE decodes to 瘀
		},
		{
			name:       "origin with null+0x01 separator (Chromium format)",
			key:        []byte("_https://desktop.cluely.com\x00\x01intercom.intercom-state"),
			wantOrigin: "https://desktop.cluely.com",
			wantKey:    "https://desktop.cluely.com :: intercom.intercom-state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry Entry
			parseChromiumKey(tt.key, &entry)

			if entry.Origin != tt.wantOrigin {
				t.Errorf("Origin = %q, want %q", entry.Origin, tt.wantOrigin)
			}

			if entry.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", entry.Key, tt.wantKey)
			}
		})
	}
}

func TestDecodeChromiumString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "regular UTF-8 bytes",
			input: []byte("hello"),
			want:  "hello",
		},
		{
			name:  "UTF-16LE encoded Hi",
			input: []byte{0x48, 0x00, 0x69, 0x00},
			want:  "Hi",
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  "",
		},
		{
			name:  "odd length falls back to UTF-8",
			input: []byte{0x41, 0x42, 0x43},
			want:  "ABC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeChromiumString(tt.input)
			if got != tt.want {
				t.Errorf("decodeChromiumString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeValue(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "plain printable UTF-16LE",
			input: []byte{0x48, 0x00, 0x69, 0x00},
			want:  "Hi",
		},
		{
			name:  "plain printable ASCII",
			input: []byte("hello world"),
			want:  "hello world",
		},
		{
			name:  "non-printable short bytes as hex",
			input: []byte{0x00, 0x02, 0x03},
			want:  "[binary: 000203]",
		},
		{
			name:  "chromium prefix 0x01 with UTF-8 JSON",
			input: append([]byte{0x01}, []byte(`{"app":"cluely","version":"1.0"}`)...),
			want:  `{"app":"cluely","version":"1.0"}`,
		},
		{
			name:  "plain UTF-8 string without prefix",
			input: []byte("plain text value"),
			want:  "plain text value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeValue(tt.input)
			if got != tt.want {
				t.Errorf("decodeValue(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseLogRecords_Valid(t *testing.T) {
	payload := []byte("hello world")
	record := makeLogRecord(RecordTypeFull, payload)

	records := parseLogRecords(record)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if string(records[0]) != "hello world" {
		t.Errorf("payload = %q, want %q", records[0], "hello world")
	}
}

func TestParseLogRecords_Empty(t *testing.T) {
	for _, input := range [][]byte{nil, {}} {
		records := parseLogRecords(input)
		if len(records) != 0 {
			t.Errorf("parseLogRecords(%v) returned %d records, want 0", input, len(records))
		}
	}
}

func TestParseLogRecords_TooShort(t *testing.T) {
	records := parseLogRecords([]byte{0x01, 0x02, 0x03})
	if len(records) != 0 {
		t.Errorf("expected 0 records for short data, got %d", len(records))
	}
}

func TestParseLogRecords_MultiPart(t *testing.T) {
	first := makeLogRecord(RecordTypeFirst, []byte("part1"))
	last := makeLogRecord(RecordTypeLast, []byte("part2"))

	combined := append(first, last...)
	records := parseLogRecords(combined)

	if len(records) != 1 {
		t.Fatalf("expected 1 reassembled record, got %d", len(records))
	}

	if string(records[0]) != "part1part2" {
		t.Errorf("payload = %q, want %q", records[0], "part1part2")
	}
}

func TestParseBatch_Valid(t *testing.T) {
	batch := buildBatch(1, ValueTypeValue, []byte("mykey"), []byte("myval"))

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	parseBatch(batch, result)

	if result.Stats.TotalEntries != 1 {
		t.Fatalf("expected 1 entry, got %d", result.Stats.TotalEntries)
	}

	if result.Stats.ValidEntries != 1 {
		t.Errorf("expected 1 valid entry, got %d", result.Stats.ValidEntries)
	}

	entry := result.Entries[0]
	if entry.Type != "value" {
		t.Errorf("entry.Type = %q, want %q", entry.Type, "value")
	}

	if entry.Sequence != 1 {
		t.Errorf("entry.Sequence = %d, want 1", entry.Sequence)
	}
}

func TestParseBatch_Empty(t *testing.T) {
	for _, input := range [][]byte{nil, {}, make([]byte, 11)} {
		result := &ParseResult{ByOrigin: make(map[string][]Entry)}
		parseBatch(input, result)

		if result.Stats.TotalEntries != 0 {
			t.Errorf("parseBatch(%v) produced %d entries, want 0", input, result.Stats.TotalEntries)
		}
	}
}

func TestParseBatch_DeleteEntry(t *testing.T) {
	batch := buildBatch(5, ValueTypeDeletion, []byte("delkey"), nil)

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	parseBatch(batch, result)

	if result.Stats.TotalEntries != 1 {
		t.Fatalf("expected 1 entry, got %d", result.Stats.TotalEntries)
	}

	if result.Stats.DeletedEntries != 1 {
		t.Errorf("expected 1 deleted entry, got %d", result.Stats.DeletedEntries)
	}

	entry := result.Entries[0]
	if entry.Type != "deletion" {
		t.Errorf("entry.Type = %q, want %q", entry.Type, "deletion")
	}
}

func TestExtractStringsFromLDB_URL(t *testing.T) {
	// Embed a URL surrounded by binary junk so the heuristic extraction finds it.
	data := append([]byte{0x00, 0x01, 0x02}, []byte("https://example.com/path?q=1")...)
	data = append(data, 0x00, 0x01, 0x02)

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	extractStringsLegacy(data, result)

	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.Key, "https://example.com") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected to extract URL string, got entries: %+v", result.Entries)
	}
}

func TestExtractStringsFromLDB_MetaPrefix(t *testing.T) {
	data := append([]byte{0x00}, []byte("META:https://origin.example.com")...)
	data = append(data, 0x00)

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	extractStringsLegacy(data, result)

	found := false
	for _, e := range result.Entries {
		if e.Type == "metadata" && strings.Contains(e.Key, "META:https://origin.example.com") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected META entry, got entries: %+v", result.Entries)
	}
}

func TestExtractStringsFromLDB_Empty(t *testing.T) {
	for _, input := range [][]byte{nil, {}} {
		result := &ParseResult{ByOrigin: make(map[string][]Entry)}
		extractStringsLegacy(input, result)

		if result.Stats.TotalEntries != 0 {
			t.Errorf("extractStringsLegacy(%v) produced %d entries, want 0", input, result.Stats.TotalEntries)
		}
	}
}

func TestExtractStringsFromLDB_HTTPOriginKey(t *testing.T) {
	// Construct a _http: prefixed key that exercises the origin extraction branch.
	data := append([]byte{0x00}, []byte("_https://app.example.com")...)
	data = append(data, 0x00)

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	extractStringsLegacy(data, result)

	found := false
	for _, e := range result.Entries {
		if e.Type == "value" && strings.Contains(e.Key, "_https://") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected _https: origin entry, got entries: %+v", result.Entries)
	}
}

func TestParseLogFile_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Build a valid log record wrapping a valid batch
	batch := buildBatch(1, ValueTypeValue, []byte("filekey"), []byte("fileval"))
	record := makeLogRecord(RecordTypeFull, batch)

	if err := os.WriteFile(logFile, record, 0o644); err != nil {
		t.Fatal(err)
	}

	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	ParseLogFile(logFile, result)

	if result.Stats.TotalEntries == 0 {
		t.Error("expected at least 1 entry from valid log file")
	}
}

func TestParseLogFile_NonExistent(t *testing.T) {
	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	ParseLogFile("/tmp/nonexistent-log-file-99999.log", result)

	if len(result.Errors) == 0 {
		t.Error("expected error for non-existent file")
	}
}

// makeLogRecord creates a single LevelDB log record with proper masked CRC32-C.
func makeLogRecord(recordType byte, payload []byte) []byte {
	typeAndData := append([]byte{recordType}, payload...)
	rawCRC := crc32.Checksum(typeAndData, crc32.MakeTable(crc32.Castagnoli))
	maskedCRC := ((rawCRC >> 15) | (rawCRC << 17)) + 0xa282ead8

	buf := make([]byte, HeaderSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], maskedCRC)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(payload)))
	buf[6] = recordType
	copy(buf[HeaderSize:], payload)

	return buf
}

// buildBatch creates a LevelDB batch with a single entry.
func buildBatch(sequence uint64, valueType byte, key, value []byte) []byte {
	var batch []byte

	seq := make([]byte, 8)
	binary.LittleEndian.PutUint64(seq, sequence)
	batch = append(batch, seq...)

	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, 1)
	batch = append(batch, count...)

	batch = append(batch, valueType)

	kl := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(kl, uint64(len(key)))
	batch = append(batch, kl[:n]...)
	batch = append(batch, key...)

	if valueType == ValueTypeValue && value != nil {
		vl := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(vl, uint64(len(value)))
		batch = append(batch, vl[:n]...)
		batch = append(batch, value...)
	}

	return batch
}

// buildLogRecord creates a minimal LevelDB log record containing a batch with one key-value pair.
func buildLogRecord(t *testing.T) []byte {
	t.Helper()

	// Build a batch: sequence(8) + count(4) + [type(1) + keylen(varint) + key + vallen(varint) + val]
	var batch []byte

	// Sequence number = 1
	seq := make([]byte, 8)
	binary.LittleEndian.PutUint64(seq, 1)
	batch = append(batch, seq...)

	// Count = 1
	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, 1)
	batch = append(batch, count...)

	// Type = value (1)
	batch = append(batch, ValueTypeValue)

	// Key: "testkey" (varint length + data)
	key := []byte("testkey")
	batch = append(batch, byte(len(key)))
	batch = append(batch, key...)

	// Value: "testval" (varint length + data)
	val := []byte("testval")
	batch = append(batch, byte(len(val)))
	batch = append(batch, val...)

	// Wrap in a log record: checksum(4) + length(2) + type(1) + data
	var record []byte

	// CRC32 checksum (Castagnoli)
	typeAndData := append([]byte{RecordTypeFull}, batch...)
	cksum := crc32.Checksum(typeAndData, crc32.MakeTable(crc32.Castagnoli))

	cksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cksumBytes, cksum)
	record = append(record, cksumBytes...)

	// Length (2 bytes LE)
	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, uint16(len(batch)))
	record = append(record, lenBytes...)

	// Record type
	record = append(record, RecordTypeFull)

	// Data
	record = append(record, batch...)

	return record
}

// buildSSTable creates a minimal SSTable with the given key-value pairs.
func buildSSTable(pairs []kvPair) []byte {
	// Build a single data block
	dataBlock := buildDataBlock(pairs)

	// Data block offset=0, uncompressed (type=0), CRC placeholder (4 bytes)
	var table []byte
	table = append(table, dataBlock...)
	table = append(table, blockTypeNoCompression) // compression type
	table = append(table, 0, 0, 0, 0)             // CRC placeholder

	dataBlockEnd := len(table)

	// Build index block with one entry pointing to data block
	dataHandle := encodeBlockHandle(blockHandle{offset: 0, size: uint64(len(dataBlock))})
	indexPairs := []kvPair{{key: []byte{0xff}, value: dataHandle}} // max key separator
	indexBlock := buildDataBlock(indexPairs)
	indexBlockOffset := dataBlockEnd
	table = append(table, indexBlock...)
	table = append(table, blockTypeNoCompression)
	table = append(table, 0, 0, 0, 0)

	// Build footer (48 bytes)
	// metaindex handle (empty: offset=0, size=0)
	metaHandle := encodeBlockHandle(blockHandle{offset: 0, size: 0})
	idxHandle := encodeBlockHandle(blockHandle{offset: uint64(indexBlockOffset), size: uint64(len(indexBlock))})

	var footer [48]byte
	copy(footer[0:], metaHandle)
	copy(footer[len(metaHandle):], idxHandle)
	binary.LittleEndian.PutUint64(footer[40:], tableMagic)
	table = append(table, footer[:]...)

	return table
}

func buildDataBlock(pairs []kvPair) []byte {
	var block []byte
	restartOffset := 0

	for _, p := range pairs {
		// shared=0, unshared=len(key), valueLen=len(value)
		block = appendUvarint(block, 0)
		block = appendUvarint(block, uint64(len(p.key)))
		block = appendUvarint(block, uint64(len(p.value)))
		block = append(block, p.key...)
		block = append(block, p.value...)
	}

	// Restart array: single restart at offset 0
	restartBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(restartBytes, uint32(restartOffset))
	block = append(block, restartBytes...)

	// Number of restarts
	numRestarts := make([]byte, 4)
	binary.LittleEndian.PutUint32(numRestarts, 1)
	block = append(block, numRestarts...)

	return block
}

func encodeBlockHandle(bh blockHandle) []byte {
	buf := make([]byte, 2*binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, bh.offset)
	n += binary.PutUvarint(buf[n:], bh.size)
	return buf[:n]
}

func appendUvarint(buf []byte, v uint64) []byte {
	tmp := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(tmp, v)
	return append(buf, tmp[:n]...)
}

func TestDeduplicateEntries(t *testing.T) {
	result := &ParseResult{
		Entries: []Entry{
			{Key: "https://example.com :: token", Origin: "https://example.com", StorageKey: "token", Value: "old", Sequence: 1, Type: "value"},
			{Key: "https://example.com :: token", Origin: "https://example.com", StorageKey: "token", Value: "new", Sequence: 5, Type: "value"},
			{Key: "https://example.com :: deleted", Origin: "https://example.com", StorageKey: "deleted", Value: "gone", Sequence: 3, Type: "value"},
			{Key: "https://example.com :: deleted", Origin: "https://example.com", StorageKey: "deleted", Value: "", Sequence: 4, Type: "deletion"},
			{Key: "META:https://example.com", Type: "metadata", Sequence: 2},
		},
		ByOrigin: make(map[string][]Entry),
	}

	deduplicateEntries(result)

	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d: %+v", len(result.Entries), result.Entries)
	}
	if result.Entries[0].Value != "new" {
		t.Errorf("expected 'new', got %q", result.Entries[0].Value)
	}
}

func TestParseSSTable_Synthetic(t *testing.T) {
	pairs := []kvPair{
		{key: []byte("_https://example.com\x00\x01mykey"), value: append([]byte{0x01}, []byte(`{"hello":"world"}`)...)},
		{key: []byte("_https://example.com\x00\x01other"), value: append([]byte{0x01}, []byte("simple value")...)},
	}

	table := buildSSTable(pairs)
	result := &ParseResult{ByOrigin: make(map[string][]Entry)}
	parseSSTable(table, result)

	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Entries))
	}

	e0 := result.Entries[0]
	if e0.Origin != "https://example.com" {
		t.Errorf("entry[0].Origin = %q, want %q", e0.Origin, "https://example.com")
	}
	if e0.StorageKey != "mykey" {
		t.Errorf("entry[0].StorageKey = %q, want %q", e0.StorageKey, "mykey")
	}
	if e0.Value != `{"hello":"world"}` {
		t.Errorf("entry[0].Value = %q, want %q", e0.Value, `{"hello":"world"}`)
	}

	e1 := result.Entries[1]
	if e1.StorageKey != "other" {
		t.Errorf("entry[1].StorageKey = %q, want %q", e1.StorageKey, "other")
	}
	if e1.Value != "simple value" {
		t.Errorf("entry[1].Value = %q, want %q", e1.Value, "simple value")
	}
}
