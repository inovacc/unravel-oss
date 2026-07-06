/*
Copyright (c) 2026 Security Research
*/
package msi

import (
	"fmt"
	"io"
)

// Database exposes a parsed MSI/MSM relational database to other packages
// (notably pkg/msm) without duplicating the CFBF + string-pool + table
// decoding logic. The same on-disk container format backs both .msi and .msm
// files; the only difference is which tables are present (an .msm carries a
// ModuleSignature table and merge-module specific tables).
type Database struct {
	tr *tableReader
}

// OpenDatabase parses the MSI database stored in a CFBF container.
func OpenDatabase(r io.ReaderAt, size int64) (*Database, error) {
	tr, err := newTableReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("open MSI database: %w", err)
	}

	return &Database{tr: tr}, nil
}

// Tables returns the list of table names declared in the database metadata.
func (d *Database) Tables() []string {
	return d.tr.tables
}

// HasTable reports whether a table with the given name is declared.
func (d *Database) HasTable(name string) bool {
	for _, t := range d.tr.tables {
		if t == name {
			return true
		}
	}

	return false
}

// StreamNames returns the decoded names of every OLE stream in the container.
func (d *Database) StreamNames() []string {
	return d.tr.streamNames()
}

// HasStream reports whether a decoded stream name exists in the container.
func (d *Database) HasStream(name string) bool {
	_, ok := d.tr.streams[name]
	return ok
}

// ReadTable returns all rows of the named table as column-keyed maps. The
// returned slice is nil when the table has no data stream.
func (d *Database) ReadTable(name string) ([]map[string]any, error) {
	return d.tr.readTable(name)
}

// StringFromRow safely extracts a string column from a table row.
func StringFromRow(row map[string]any, key string) string {
	return stringVal(row, key)
}

// IntFromRow safely extracts an integer column from a table row.
func IntFromRow(row map[string]any, key string) int {
	if v, ok := row[key]; ok {
		return intVal(v)
	}

	return 0
}
