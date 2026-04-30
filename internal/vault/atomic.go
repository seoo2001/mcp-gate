package vault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// writeAtomic mirrors keystore.writeAtomic: temp + fsync + rename. Duplicated
// here rather than imported to keep the dependency direction one-way (vault
// depends on keystore, not the other way).
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-")
	if err != nil {
		return fmt.Errorf("vault write: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vault write: write: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("vault write: chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vault write: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault write: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("vault write: rename: %w", err)
	}
	return nil
}
