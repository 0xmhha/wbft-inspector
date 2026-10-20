package rejections

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalProposalOriginRemainsDistinct(t *testing.T) {
	local := strings.Replace(recA, `"path":"preprepare"`, `"path":"local_reproposal"`, 1)
	for _, response := range []bool{false, true} {
		body := recA + "\n" + local + "\n"
		if response {
			body = `{"jsonrpc":"2.0","id":1,"result":[` + recA + "," + local + `]}`
		}
		p := filepath.Join(t.TempDir(), "rejections.json")
		write(t, p, body)
		set, err := Load("0xabc", p)
		if err != nil || len(set.Problems) != 0 || len(set.Records) != 2 || set.SHA256 == "" {
			t.Fatal(set, err)
		}
		if set.Records[0].Path != "preprepare" || set.Records[1].Path != "local_reproposal" || set.Records[0].Hash != set.Records[1].Hash {
			t.Fatal("local origin was combined with received-proposal evidence", set.Records)
		}
	}
}
