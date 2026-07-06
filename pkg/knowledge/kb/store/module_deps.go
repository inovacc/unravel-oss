/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"database/sql"
	"fmt"
)

// BackfillModuleDepsToID populates module_deps.to_id for rows where to_id
// IS NULL by looking up the dep name inside the same app. Returns the
// number of rows resolved. Rows that don't match any sibling stay NULL
// (external deps).
func BackfillModuleDepsToID(db *sql.DB) (int64, error) {
	res, err := db.Exec(`
		UPDATE module_deps
		   SET to_id = (
		     SELECT m2.id
		       FROM modules m2
		       JOIN modules m1 ON m1.id = module_deps.from_id
		      WHERE m2.app = m1.app AND m2.name = module_deps.to_name
		      LIMIT 1
		   )
		 WHERE to_id IS NULL
	`)
	if err != nil {
		return 0, fmt.Errorf("backfill to_id: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
