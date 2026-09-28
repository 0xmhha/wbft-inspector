package yamlsubset

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsesPublishedVectors parses every file of a wbft-spec vector
// directory when WBFT_SPEC_VECTORS names one.
func TestParsesPublishedVectors(t *testing.T) {
	dir := os.Getenv("WBFT_SPEC_VECTORS")
	if dir == "" {
		t.Skip("WBFT_SPEC_VECTORS is not set")
	}
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := Parse(b); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files", n)
}
