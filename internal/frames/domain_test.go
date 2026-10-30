package frames

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Only fresh unsigned JSON declarations are loaded. No node, signed message,
// retained input, or runtime journal is altered.
func TestUnboundDomainMarkerDiscardsWholeDump(t *testing.T) {
	for _, field := range []string{"signing_profile", "round_change_domain"} {
		for _, value := range []string{`null`, `{}`, `"unavailable"`} {
			dir := t.TempDir()
			prefix := `{"v":1,"type":"conn","node":"0x0000000000000000000000000000000000000001","run":"model","seq":1,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"peer":"0x0000000000000000000000000000000000000002","event":"istanbul_attached"}`
			record := fmt.Sprintf(`{"%s":%s}`, field, value)
			if err := os.WriteFile(filepath.Join(dir, "frames-model.jsonl"), []byte(prefix+"\n"+record+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			dump, err := Load(dir)
			if !errors.Is(err, ErrDomainUnsupported) || dump != nil {
				t.Fatal("selected marker became a legacy or damaged prefix", field, value, dump, err)
			}
		}
	}
}
