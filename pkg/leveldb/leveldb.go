// Package leveldb parses LevelDB databases used by Chromium for localStorage and sessionStorage.
package leveldb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/golang/snappy"
)

// LevelDB constants
const (
	RecordTypeFull   = 1
	RecordTypeFirst  = 2
	RecordTypeMiddle = 3
	RecordTypeLast   = 4

	ValueTypeDeletion = 0
	ValueTypeValue    = 1

	BlockSize  = 32768
	HeaderSize = 7

	tableFooterLen         = 48
	tableMagic             = 0xdb4775248b80fb57
	blockTypeNoCompression = 0
	blockTypeSnappy        = 1

	// maxLogResyncScanBytes caps the cumulative byte-by-byte resync distance
	// spent recovering from CRC mismatches in a single .log file. Encrypted or
	// opaque stores (e.g. WhatsApp's EBWebView IndexedDB) never CRC-match;
	// without this cap the byte-wise resync is O(n^2) over hundreds of MB.
	// A LevelDB physical block is 32 KiB; 1 MiB tolerates ~32 torn blocks of
	// genuine corruption recovery before declaring a store unreadable.
	maxLogResyncScanBytes = 1 << 20

	// maxLevelDBFileBytes bounds a single .log/.ldb/.sst file read so a
	// pathologically large store cannot exhaust memory.
	maxLevelDBFileBytes = 256 << 20
)

// castagnoliTable is built once and reused for every LevelDB record CRC.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// Entry represents a single LevelDB key-value entry.
type Entry struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	RawKey     string `json:"raw_key,omitempty"`
	RawValue   string `json:"raw_value_hex,omitempty"`
	Decoded    any    `json:"decoded,omitempty"`
	Origin     string `json:"origin,omitempty"`
	StorageKey string `json:"storage_key,omitempty"`
	Sequence   uint64 `json:"sequence,omitempty"`
	Type       string `json:"type"`
}

// ParseResult holds the complete result of parsing a LevelDB directory.
type ParseResult struct {
	SourcePath  string             `json:"source_path"`
	ParsedAt    string             `json:"parsed_at"`
	StorageType string             `json:"storage_type"`
	Entries     []Entry            `json:"entries"`
	ByOrigin    map[string][]Entry `json:"by_origin,omitempty"`
	Errors      []string           `json:"errors,omitempty"`
	Stats       ParseStats         `json:"stats"`
}

// ParseStats contains statistics about the parsing operation.
type ParseStats struct {
	TotalEntries   int `json:"total_entries"`
	ValidEntries   int `json:"valid_entries"`
	DeletedEntries int `json:"deleted_entries"`
	ParseErrors    int `json:"parse_errors"`
	LogFiles       int `json:"log_files_parsed"`
	LDBFiles       int `json:"ldb_files_parsed"`
}

// ParseDirectory parses all LevelDB files in the given directory and returns the result.
func ParseDirectory(sourcePath string) (*ParseResult, error) {
	if _, err := os.Stat(sourcePath); err != nil {
		return nil, fmt.Errorf("path does not exist: %w", err)
	}

	baseName := strings.ToLower(filepath.Base(sourcePath))
	storageType := "unknown"

	switch {
	case strings.Contains(baseName, "local"):
		storageType = "localStorage"
	case strings.Contains(baseName, "session"):
		storageType = "sessionStorage"
	case strings.Contains(baseName, "indexeddb"):
		storageType = "indexedDB"
	}

	result := &ParseResult{
		SourcePath:  sourcePath,
		ParsedAt:    time.Now().UTC().Format(time.RFC3339),
		StorageType: storageType,
		Entries:     []Entry{},
		ByOrigin:    make(map[string][]Entry),
		Errors:      []string{},
	}

	// DEBUG: one line per store opened. Gated behind slog DEBUG level so it
	// is silent unless --debug is on (matching the recorder semantics). No
	// extra traversal, no behavior change.
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("leveldb store opened",
			"store_path", sourcePath,
			"storage_type", storageType,
		)
	}

	parseDir(sourcePath, result)
	deduplicateEntries(result)
	organizeByOrigin(result)

	// DEBUG: per-origin record tally, reusing the counters already built by
	// organizeByOrigin (no new pass over the data).
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		for origin, entries := range result.ByOrigin {
			slog.Debug("leveldb origin tally",
				"store_path", sourcePath,
				"origin", origin,
				"record_count", len(entries),
			)
		}
	}

	return result, nil
}

func parseDir(path string, result *ParseResult) {
	leveldbPath := path
	if _, err := os.Stat(filepath.Join(path, "leveldb")); err == nil {
		leveldbPath = filepath.Join(path, "leveldb")
	}

	logFiles, _ := filepath.Glob(filepath.Join(leveldbPath, "*.log"))
	for _, logFile := range logFiles {
		ParseLogFile(logFile, result)
		result.Stats.LogFiles++
	}

	ldbFiles, _ := filepath.Glob(filepath.Join(leveldbPath, "*.ldb"))
	for _, ldbFile := range ldbFiles {
		ParseLDBFile(ldbFile, result)
		result.Stats.LDBFiles++
	}

	sstFiles, _ := filepath.Glob(filepath.Join(leveldbPath, "*.sst"))
	for _, sstFile := range sstFiles {
		ParseLDBFile(sstFile, result)
		result.Stats.LDBFiles++
	}
}

// ParseLogFile parses a single LevelDB .log file.
func ParseLogFile(path string, result *ParseResult) {
	data, err := readBoundedFile(path)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read %s: %v", path, err))
		return
	}

	records := parseLogRecords(data)
	for _, record := range records {
		parseBatch(record, result)
	}
}

// ParseLDBFile parses a single .ldb or .sst file using SSTable format.
func ParseLDBFile(path string, result *ParseResult) {
	data, err := readBoundedFile(path)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read %s: %v", path, err))
		return
	}

	parseSSTable(data, result)
}

// errFileTooLarge is returned when a LevelDB file exceeds maxLevelDBFileBytes.
var errFileTooLarge = fmt.Errorf("leveldb file exceeds %d byte cap", maxLevelDBFileBytes)

// readBoundedFile reads a LevelDB file, rejecting it (non-fatally, surfaced via
// the caller's result.Errors) when it exceeds maxLevelDBFileBytes.
func readBoundedFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() > maxLevelDBFileBytes {
		return nil, fmt.Errorf("%s: %w", path, errFileTooLarge)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

type blockHandle struct {
	offset uint64
	size   uint64
}

type kvPair struct {
	key   []byte
	value []byte
}

func parseSSTable(data []byte, result *ParseResult) {
	if len(data) < tableFooterLen {
		extractStringsLegacy(data, result)
		return
	}

	footer := data[len(data)-tableFooterLen:]
	magic := binary.LittleEndian.Uint64(footer[40:48])
	if magic != tableMagic {
		extractStringsLegacy(data, result)
		return
	}

	// Parse metaindex and index block handles from footer
	_, n1 := decodeBlockHandle(footer)
	if n1 == 0 {
		return
	}
	indexHandle, n2 := decodeBlockHandle(footer[n1:])
	if n2 == 0 {
		return
	}

	indexBlock, ok := readBlock(data, indexHandle)
	if !ok {
		return
	}

	dataHandles := parseBlockEntries(indexBlock)

	for _, dh := range dataHandles {
		block, ok := readBlock(data, dh)
		if !ok {
			continue
		}
		entries := parseDataBlock(block)
		for _, kv := range entries {
			entry := Entry{
				RawKey: hex.EncodeToString(kv.key),
				Type:   "value",
			}
			parseChromiumKey(kv.key, &entry)
			entry.Value = decodeValue(kv.value)
			if dec, ok := DecodeIndexedDBValue(kv.value); ok {
				entry.Decoded = dec
			}
			entry.RawValue = hex.EncodeToString(kv.value)
			result.Entries = append(result.Entries, entry)
			result.Stats.TotalEntries++
			result.Stats.ValidEntries++
		}
	}
}

func decodeBlockHandle(data []byte) (blockHandle, int) {
	offset, n1 := binary.Uvarint(data)
	if n1 <= 0 {
		return blockHandle{}, 0
	}
	size, n2 := binary.Uvarint(data[n1:])
	if n2 <= 0 {
		return blockHandle{}, 0
	}
	return blockHandle{offset: offset, size: size}, n1 + n2
}

func readBlock(data []byte, bh blockHandle) ([]byte, bool) {
	// Block format: [data][compression_type:1][crc32:4]
	// Check bounds without addition to avoid uint64 overflow:
	//   require bh.offset <= len(data) AND bh.size+5 <= len(data)-bh.offset.
	dlen := uint64(len(data))
	if bh.offset > dlen {
		return nil, false
	}
	remaining := dlen - bh.offset
	// bh.size+5 could overflow if bh.size is near MaxUint64; check size first.
	if bh.size > remaining || 5 > remaining-bh.size {
		return nil, false
	}
	raw := data[bh.offset : bh.offset+bh.size]
	blockType := data[bh.offset+bh.size]

	switch blockType {
	case blockTypeNoCompression:
		return raw, true
	case blockTypeSnappy:
		decoded, err := snappy.Decode(nil, raw)
		if err != nil {
			return nil, false
		}
		return decoded, true
	default:
		return raw, true
	}
}

func parseDataBlock(block []byte) []kvPair {
	if len(block) < 4 {
		return nil
	}

	numRestarts := int(binary.LittleEndian.Uint32(block[len(block)-4:]))
	restartsStart := len(block) - 4 - 4*numRestarts
	if restartsStart < 0 {
		return nil
	}

	var pairs []kvPair
	var prevKey []byte
	offset := 0

	for offset < restartsStart {
		shared, n1 := binary.Uvarint(block[offset:])
		if n1 <= 0 {
			break
		}
		offset += n1

		unshared, n2 := binary.Uvarint(block[offset:])
		if n2 <= 0 {
			break
		}
		offset += n2

		valueLen, n3 := binary.Uvarint(block[offset:])
		if n3 <= 0 {
			break
		}
		offset += n3

		if offset+int(unshared)+int(valueLen) > restartsStart {
			break
		}

		// SEC: guard against uint64 overflow when summing shared+unshared before make.
		// If shared or unshared each exceed the block length, or their sum wraps,
		// the resulting make would be zero-length and the subsequent copy would OOB.
		if shared > uint64(restartsStart) || unshared > uint64(restartsStart) {
			break
		}
		keyLen64 := shared + unshared
		if keyLen64 < shared { // overflow
			break
		}
		if keyLen64 > uint64(restartsStart) {
			break
		}

		key := make([]byte, keyLen64)
		if shared > 0 && int(shared) <= len(prevKey) {
			copy(key, prevKey[:shared])
		}
		copy(key[shared:], block[offset:offset+int(unshared)])
		offset += int(unshared)

		value := make([]byte, valueLen)
		copy(value, block[offset:offset+int(valueLen)])
		offset += int(valueLen)

		prevKey = key
		pairs = append(pairs, kvPair{key: key, value: value})
	}

	return pairs
}

func parseBlockEntries(block []byte) []blockHandle {
	pairs := parseDataBlock(block)
	var handles []blockHandle
	for _, p := range pairs {
		bh, _ := decodeBlockHandle(p.value)
		if bh.size > 0 {
			handles = append(handles, bh)
		}
	}
	return handles
}

func parseLogRecords(data []byte) [][]byte {
	var (
		records       [][]byte
		currentRecord []byte
	)

	offset := 0
	resyncBytes := 0
	for offset < len(data) {
		if offset+HeaderSize > len(data) {
			break
		}

		checksum := binary.LittleEndian.Uint32(data[offset:])
		length := binary.LittleEndian.Uint16(data[offset+4:])
		recordType := data[offset+6]

		if offset+HeaderSize+int(length) > len(data) {
			break
		}

		payload := data[offset+HeaderSize : offset+HeaderSize+int(length)]

		// CRC over recordType byte then payload, with no per-record allocation
		// and a package-scope Castagnoli table reused across all records.
		crc := crc32.Update(0, castagnoliTable, []byte{recordType})
		crc = crc32.Update(crc, castagnoliTable, payload)
		maskedCRC := ((crc >> 15) | (crc << 17)) + 0xa282ead8

		if checksum != maskedCRC {
			// Encrypted/opaque stores never CRC-match. Cap the cumulative
			// byte-wise resync so we abandon corrupt/encrypted stores as
			// honest-empty instead of an O(n^2) scan to EOF.
			resyncBytes++
			if resyncBytes > maxLogResyncScanBytes {
				break
			}
			offset++
			continue
		}

		switch recordType {
		case RecordTypeFull:
			records = append(records, payload)
			currentRecord = nil
		case RecordTypeFirst:
			currentRecord = make([]byte, len(payload))
			copy(currentRecord, payload)
		case RecordTypeMiddle:
			if currentRecord != nil {
				currentRecord = append(currentRecord, payload...)
			}
		case RecordTypeLast:
			if currentRecord != nil {
				currentRecord = append(currentRecord, payload...)
				records = append(records, currentRecord)
				currentRecord = nil
			}
		}

		offset += HeaderSize + int(length)

		blockOffset := offset % BlockSize
		if blockOffset > 0 && blockOffset+HeaderSize > BlockSize {
			offset += BlockSize - blockOffset
		}
	}

	return records
}

func parseBatch(data []byte, result *ParseResult) {
	if len(data) < 12 {
		return
	}

	sequence := binary.LittleEndian.Uint64(data[0:8])
	count := binary.LittleEndian.Uint32(data[8:12])

	offset := 12
	for i := uint32(0); i < count && offset < len(data); i++ {
		if offset >= len(data) {
			break
		}

		valueType := data[offset]
		offset++

		keyLen, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			result.Stats.ParseErrors++
			break
		}

		offset += n

		// SEC: use uint64 arithmetic for the bounds check to avoid int overflow on
		// 32-bit builds where int(keyLen) with keyLen=0xFFFFFFFF wraps negative.
		if keyLen > uint64(len(data)-offset) {
			result.Stats.ParseErrors++
			break
		}

		key := data[offset : offset+int(keyLen)]
		offset += int(keyLen)

		entry := Entry{
			Sequence: sequence,
			RawKey:   hex.EncodeToString(key),
		}

		if valueType == ValueTypeValue {
			valueLen, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				result.Stats.ParseErrors++
				break
			}

			offset += n

			// SEC: uint64 bounds check before int cast (same rationale as keyLen).
			if valueLen > uint64(len(data)-offset) {
				result.Stats.ParseErrors++
				break
			}

			value := data[offset : offset+int(valueLen)]
			offset += int(valueLen)

			entry.Type = "value"
			entry.RawValue = hex.EncodeToString(value)

			parseChromiumKey(key, &entry)
			entry.Value = decodeValue(value)
			if dec, ok := DecodeIndexedDBValue(value); ok {
				entry.Decoded = dec
			}

			result.Stats.ValidEntries++
		} else {
			entry.Type = "deletion"
			parseChromiumKey(key, &entry)

			result.Stats.DeletedEntries++
		}

		result.Entries = append(result.Entries, entry)
		result.Stats.TotalEntries++
	}
}

func extractStringsLegacy(data []byte, result *ParseResult) {
	var currentKey []byte

	inKey := false

	for i := 0; i < len(data); i++ {
		if i+5 < len(data) && string(data[i:i+5]) == "META:" {
			end := i + 5
			for end < len(data) && data[end] != 0 {
				end++
			}

			if end > i+5 {
				key := string(data[i:end])
				entry := Entry{Key: key, Type: "metadata"}
				result.Entries = append(result.Entries, entry)
				result.Stats.TotalEntries++
			}

			i = end

			continue
		}

		if i+6 < len(data) && (string(data[i:i+6]) == "_http:" || (i+7 < len(data) && string(data[i:i+7]) == "_https:")) {
			end := i
			for end < len(data) && data[end] != 0 && data[end] >= 32 && data[end] < 127 {
				end++
			}

			if end > i {
				keyStr := string(data[i:end])
				entry := Entry{Key: keyStr, Type: "value"}

				parts := strings.SplitN(keyStr[1:], "\x00", 2)
				if len(parts) >= 1 {
					entry.Origin = parts[0]
				}

				if len(parts) >= 2 {
					entry.StorageKey = parts[1]
				}

				result.Entries = append(result.Entries, entry)
				result.Stats.TotalEntries++
				result.Stats.ValidEntries++
			}

			i = end

			continue
		}

		if data[i] >= 32 && data[i] < 127 {
			if !inKey {
				currentKey = []byte{data[i]}
				inKey = true
			} else {
				currentKey = append(currentKey, data[i])
			}
		} else {
			if inKey && len(currentKey) > 10 {
				keyStr := string(currentKey)
				if strings.Contains(keyStr, "http") ||
					strings.Contains(keyStr, "token") ||
					strings.Contains(keyStr, "key") ||
					strings.Contains(keyStr, "api") ||
					strings.Contains(keyStr, "user") ||
					strings.Contains(keyStr, "session") {
					entry := Entry{Key: keyStr, Type: "extracted_string"}
					result.Entries = append(result.Entries, entry)
					result.Stats.TotalEntries++
				}
			}

			currentKey = nil
			inKey = false
		}
	}
}

func parseChromiumKey(key []byte, entry *Entry) {
	if len(key) == 0 {
		return
	}

	// Strip leading underscore (Chromium convention)
	if key[0] == '_' {
		key = key[1:]
	}

	nullIdx := bytes.IndexByte(key, 0)
	if nullIdx > 0 {
		entry.Origin = string(key[:nullIdx])
		remainder := key[nullIdx+1:]
		// Skip Chromium's 0x01 prefix byte if present
		if len(remainder) > 0 && remainder[0] == 0x01 {
			remainder = remainder[1:]
		}
		if len(remainder) > 0 {
			entry.StorageKey = decodeChromiumString(remainder)
			entry.Key = entry.Origin + " :: " + entry.StorageKey
		} else {
			entry.Key = entry.Origin
		}
	} else {
		entry.Key = decodeChromiumString(key)
	}
}

func decodeValue(value []byte) string {
	if len(value) == 0 {
		return ""
	}

	// Chromium localStorage prefix: 0x01 = UTF-8 string
	if value[0] == 0x01 && len(value) > 1 {
		payload := value[1:]
		if s := string(payload); isPrintable(s) {
			return s
		}
	}

	// Try plain UTF-8 first
	if s := string(value); isPrintable(s) {
		return s
	}

	// Try UTF-16LE
	if decoded := decodeUTF16LE(value); decoded != "" && isPrintable(decoded) {
		return decoded
	}

	// Binary fallback
	if len(value) > 100 {
		return fmt.Sprintf("[binary data: %d bytes]", len(value))
	}
	return fmt.Sprintf("[binary: %s]", hex.EncodeToString(value))
}

func decodeChromiumString(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Try UTF-8 first — most Chromium keys are ASCII
	if s := string(data); isPrintable(s) {
		return s
	}

	// Fall back to UTF-16LE
	if decoded := decodeUTF16LE(data); decoded != "" && isPrintable(decoded) {
		return decoded
	}

	return string(data)
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 || len(data)%2 != 0 {
		return ""
	}

	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	runes := utf16.Decode(u16s)

	return string(runes)
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}

	return true
}

func deduplicateEntries(result *ParseResult) {
	type entryKey struct {
		origin     string
		storageKey string
	}

	best := make(map[entryKey]Entry)
	deleted := make(map[entryKey]uint64)

	for _, e := range result.Entries {
		if e.Type == "metadata" || e.Type == "extracted_string" {
			continue
		}

		ek := entryKey{origin: e.Origin, storageKey: e.StorageKey}
		if ek.storageKey == "" {
			ek.storageKey = e.Key
		}

		if e.Type == "deletion" {
			if e.Sequence > deleted[ek] {
				deleted[ek] = e.Sequence
			}
			continue
		}

		if existing, ok := best[ek]; !ok || e.Sequence > existing.Sequence {
			best[ek] = e
		}
	}

	var deduped []Entry
	for ek, e := range best {
		if delSeq, ok := deleted[ek]; ok && delSeq > e.Sequence {
			continue
		}
		deduped = append(deduped, e)
	}

	result.Entries = deduped
	result.Stats.ValidEntries = len(deduped)
}

func organizeByOrigin(result *ParseResult) {
	for _, entry := range result.Entries {
		origin := entry.Origin
		if origin == "" {
			origin = "unknown"
		}

		result.ByOrigin[origin] = append(result.ByOrigin[origin], entry)
	}
}

// FormatSummary returns a human-readable summary string.
func FormatSummary(result *ParseResult) string {
	var buf bytes.Buffer

	buf.WriteString("LevelDB Parse Summary\n")
	buf.WriteString("=====================\n\n")
	buf.WriteString(fmt.Sprintf("Source: %s\n", result.SourcePath))
	buf.WriteString(fmt.Sprintf("Storage Type: %s\n", result.StorageType))
	buf.WriteString(fmt.Sprintf("Parsed At: %s\n\n", result.ParsedAt))

	buf.WriteString("Statistics\n")
	buf.WriteString("----------\n")
	buf.WriteString(fmt.Sprintf("Total Entries: %d\n", result.Stats.TotalEntries))
	buf.WriteString(fmt.Sprintf("Valid Entries: %d\n", result.Stats.ValidEntries))
	buf.WriteString(fmt.Sprintf("Deleted Entries: %d\n", result.Stats.DeletedEntries))
	buf.WriteString(fmt.Sprintf("Parse Errors: %d\n", result.Stats.ParseErrors))
	buf.WriteString(fmt.Sprintf("Log Files Parsed: %d\n", result.Stats.LogFiles))
	buf.WriteString(fmt.Sprintf("LDB Files Parsed: %d\n\n", result.Stats.LDBFiles))

	buf.WriteString("Origins Found\n")
	buf.WriteString("-------------\n")

	origins := make([]string, 0, len(result.ByOrigin))
	for origin := range result.ByOrigin {
		origins = append(origins, origin)
	}

	sort.Strings(origins)

	for _, origin := range origins {
		entries := result.ByOrigin[origin]
		buf.WriteString(fmt.Sprintf("  %s: %d entries\n", origin, len(entries)))
	}

	return buf.String()
}
