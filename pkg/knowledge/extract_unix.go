//go:build !windows

package knowledge

import "os"

// openFileShared opens a file for reading. On Unix, file locking is advisory
// so os.Open works even on locked files.
func openFileShared(path string) (*os.File, error) {
	return os.Open(path)
}
