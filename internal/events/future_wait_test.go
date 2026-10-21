package events

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFutureProposalWaitObservations(t *testing.T) {
	lines := `{"v":1,"node":"0x00000000000000000000000000000000000000aa","run":"wait-limit","seq":0,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft"}
{"v":1,"node":"0x00000000000000000000000000000000000000aa","run":"wait-limit","seq":1,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":1,"kind":"HEALTH","view":{"seq":"18446744073709551616","round":"0"},"step":1,"engine_run":1,"what":"future_proposal_wait_exceeded","h":"18446744073709551616","hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposal_origin":"preprepare","wait_ns":"3000000000","limit_ns":"2000000000"}
{"v":1,"node":"0x00000000000000000000000000000000000000aa","run":"wait-limit","seq":2,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":2,"kind":"HEALTH","view":{"seq":"18446744073709551616","round":"1"},"step":2,"engine_run":1,"what":"future_proposal_wait_exceeded","h":"18446744073709551616","hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proposal_origin":"local_reproposal","wait_ns":"5000000000","limit_ns":"4000000000"}
`
	p := filepath.Join(t.TempDir(), "wait-limit.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := Load([]string{p})
	if err != nil || len(set.Errors) != 0 || len(set.UnknownKinds) != 0 || len(set.Runs) != 1 {
		t.Fatal(set, err)
	}
	records := set.Runs[0].Events
	if len(records) != 3 {
		t.Fatal("missing wait observations", records)
	}
	for i, expected := range []struct{ origin, wait, limit string }{{"preprepare", "3000000000", "2000000000"}, {"local_reproposal", "5000000000", "4000000000"}} {
		r := records[i+1]
		if r.Str("what") != "future_proposal_wait_exceeded" || r.Str("proposal_origin") != expected.origin || r.Str("wait_ns") != expected.wait || r.Str("limit_ns") != expected.limit || r.View == nil || r.View.Seq != "18446744073709551616" || r.Str("h") != r.View.Seq {
			t.Fatal("closed wait metadata lost", r)
		}
	}
	if !loadSchema(t).values["what"]["future_proposal_wait_exceeded"] || !loadSchema(t).values["proposal_origin"]["preprepare"] || !loadSchema(t).values["proposal_origin"]["local_reproposal"] {
		t.Fatal("wait observation vocabulary absent from producer schema")
	}
}
