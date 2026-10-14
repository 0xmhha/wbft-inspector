package observations

import (
	"fmt"
	"strings"
	"testing"
)

func row(seq int, fields string) string {
	return fmt.Sprintf(`{"v":1,"node":"0x1111111111111111111111111111111111111111","run":"synthetic","seq":%d,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":%d,%s}`+"\n", seq, seq, fields)
}
func fixture() string {
	return row(0, `"type":"runtime_start","config":{"Address":"0x1111111111111111111111111111111111111111","Height":"18446744073709551616","RequestTimeoutMS":"1000","BlockPeriodSeconds":"1","Epoch":"10","AllowedFutureBlockSeconds":"2","MaxRequestTimeoutSeconds":"0","ProposerPolicy":"0","Transitions":0,"SystemContractUpgrades":0}`) + row(1, `"type":"operation_start","id":18446744073709551615,"operation":"worker_commit_work","height":"","hash":"","count":1`) + row(2, `"type":"operation_end","id":18446744073709551615,"result":"returned","height":"18446744073709551616","hash":"","index":0`) + row(3, `"type":"runtime_close","engine_stopped":false`) + row(4, `"type":"capture_end","dropped":0`)
}
func TestExactCallsRetainLargeIdentityWithoutModelClaims(t *testing.T) {
	x, e := Read(strings.NewReader(fixture()))
	if e != nil || !x.CaptureComplete || len(x.Calls) != 1 || x.Calls[0].ID != "18446744073709551615" || x.Calls[0].Nanoseconds != "1" || x.Calls[0].Height != "18446744073709551616" || x.RuntimeModelComplete || x.DeliveryCoverageProven || x.ApplicationRequestCompletionProven {
		t.Fatal(x, e)
	}
}
func TestInvalidEvidenceIsRefusedWithoutEchoingInput(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"duplicate", "\"v\":1", "\"v\":1,\"v\":1"},
		{"nested_duplicate", "\"Height\":\"18446744073709551616\"", "\"Height\":\"1\",\"Height\":\"2\""},
		{"null", "\"dropped\":0", "\"dropped\":null"},
		{"unknown", "\"dropped\":0", "\"dropped\":0,\"private\":\"private-value\""},
		{"stop_claim", "\"engine_stopped\":false", "\"engine_stopped\":true"},
		{"duplicate_start", "\"type\":\"operation_end\"", "\"type\":\"operation_start\""},
		{"identity", "\"run\":\"synthetic\"", "\"run\":\"private-value/unsafe\""},
		{"fraction", "\"seq\":1", "\"seq\":1.5"},
		{"drop_mismatch", "\"dropped\":0", "\"dropped\":1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := Read(strings.NewReader(strings.Replace(fixture(), tc.old, tc.new, 1)))
			if e == nil || strings.Contains(e.Error(), "private-value") {
				t.Fatal(e)
			}
		})
	}
}
func TestMissingBoundariesStayUnavailable(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(fixture()), "\n")
	x, e := Read(strings.NewReader(strings.Join(lines[:4], "\n")))
	if e != nil || x.CaptureComplete || len(x.Unavailable) == 0 {
		t.Fatal(x, e)
	}
	incomplete := row(0, `"type":"operation_end","id":1,"result":"ok","height":"1","hash":"","index":0`) + row(1, `"type":"capture_end","dropped":0`)
	x, e = Read(strings.NewReader(incomplete))
	if e != nil || x.CaptureComplete || len(x.Calls) != 0 {
		t.Fatal(x, e)
	}
}
func TestRecordAfterEndAndReversedCallAreRefused(t *testing.T) {
	_, e := Read(strings.NewReader(fixture() + row(5, `"type":"runtime_close","engine_stopped":false`)))
	if e == nil {
		t.Fatal("accepted record after final boundary")
	}
	_, e = Read(strings.NewReader(strings.Replace(fixture(), `"t_mono_ns":2`, `"t_mono_ns":0`, 1)))
	if e == nil {
		t.Fatal("accepted reversed interval")
	}
}

func TestBoundedReaderAndReportedDrops(t *testing.T) {
	if _, e := Read(strings.NewReader(strings.Repeat("x", 65538))); e == nil {
		t.Fatal("oversized line allowed")
	}
	lines := strings.Split(strings.TrimSpace(fixture()), "\n")
	// A dropped non-boundary record leaves valid observed calls but incomplete capture.
	for i := 3; i < len(lines); i++ {
		lines[i] = strings.Replace(lines[i], fmt.Sprintf(`"seq":%d`, i), fmt.Sprintf(`"seq":%d`, i+1), 1)
	}
	lines[4] = strings.Replace(lines[4], `"dropped":0`, `"dropped":1`, 1)
	x, e := Read(strings.NewReader(strings.Join(lines, "\n")))
	if e != nil || x.CaptureComplete || x.SequenceGaps != "1" || len(x.Calls) != 1 {
		t.Fatal(x, e)
	}
}
