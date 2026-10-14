package observations

import (
	"fmt"
	"strings"
	"testing"
)

func taskInput(stages []string) string {
	base := strings.Split(strings.TrimSpace(fixture()), "\n")
	out := strings.Join(base[:4], "\n") + "\n"
	for i, stage := range stages {
		out += row(i+4, fmt.Sprintf(`"type":"operation_stage","id":18446744073709551615,"stage":%q,"height":"18446744073709551616","hash":"0x%s"`, stage, strings.Repeat("2", 64)))
	}
	return out + row(4+len(stages), `"type":"capture_end","dropped":0`)
}
func TestTaskTokenSeparatesReturnAndAsynchronousCompletion(t *testing.T) {
	stages := []string{"task_offer", "task_received", "seal_enter", "seal_return", "task_sent", "request_post_enter", "request_post_return"}
	got, e := Read(strings.NewReader(taskInput(stages)))
	if e != nil || len(got.Tasks) != 1 || got.Tasks[0].State != "incomplete" {
		t.Fatal(got, e)
	}
	for _, tc := range []struct{ stage, state string }{{"seal_result", "observed_result"}, {"seal_cancel", "observed_cancellation"}} {
		got, e = Read(strings.NewReader(taskInput(append(append([]string(nil), stages...), tc.stage))))
		if e != nil || got.Format != "wbft-tap-observations/2" || got.Tasks[0].State != tc.state || got.Tasks[0].ID != "18446744073709551615" || got.Tasks[0].StartLine != 2 || got.Tasks[0].EndLine != 3 || len(got.Tasks[0].Stages) != 8 || got.ApplicationRequestCompletionProven {
			t.Fatal(got, e)
		}
	}
	duplicate := append(append([]string(nil), stages...), "seal_result", "seal_result")
	got, e = Read(strings.NewReader(taskInput(duplicate)))
	if e != nil || got.Tasks[0].State != "ambiguous" || len(got.Tasks[0].Stages) != 9 {
		t.Fatal("duplicate stage lost", got, e)
	}
}
func TestTaskStageRequiresExactParentAndFullIdentity(t *testing.T) {
	for _, tc := range []struct{ old, new string }{{`"id":18446744073709551615,"stage"`, `"id":1,"stage"`}, {`"stage":"task_offer"`, `"stage":"unknown"`}, {`"stage":"task_offer"`, `"stage":null`}} {
		raw := strings.Replace(taskInput([]string{"task_offer"}), tc.old, tc.new, 1)
		if _, e := Read(strings.NewReader(raw)); e == nil {
			t.Fatal("invalid stage accepted")
		}
	}
	for _, stages := range [][]string{{"task_offer", "task_abandoned", "task_sent"}, {"task_offer", "task_sent", "task_received", "task_duplicate", "seal_enter"}} {
		got, e := Read(strings.NewReader(taskInput(stages)))
		if e != nil || got.Tasks[0].State != "ambiguous" {
			t.Fatal(got, e)
		}
	}
}
