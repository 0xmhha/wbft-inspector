package observations

import (
	"fmt"
	"strings"
	"testing"
)

func engineInput(stages []string) string {
	fields := []string{strings.Split(strings.TrimSpace(fixture()), "\n")[0]}
	// Preserve the startup config, replacing the common envelope below.
	fields[0] = fields[0][strings.Index(fields[0], `"type"`):]
	fields[0] = strings.TrimSuffix(fields[0], "}")
	fields = append(fields, `"type":"operation_start","id":1,"operation":"backend_start","height":"","hash":"","count":0`, `"type":"engine_created","id":18446744073709551615,"parent_id":1`)
	for _, s := range stages {
		parent := 1
		if engineStopStage(s) {
			parent = 2
		}
		if s == "stop_enter" {
			fields = append(fields, `"type":"operation_end","id":1,"result":"ok","height":"","hash":"","index":0`, `"type":"operation_start","id":2,"operation":"backend_stop","height":"","hash":"","count":0`)
		}
		fields = append(fields, fmt.Sprintf(`"type":"engine_stage","id":18446744073709551615,"parent_id":%d,"stage":%q`, parent, s))
	}
	if !strings.Contains(strings.Join(stages, ","), "stop_enter") {
		fields = append(fields, `"type":"operation_end","id":1,"result":"ok","height":"","hash":"","index":0`)
	} else {
		fields = append(fields, `"type":"operation_end","id":2,"result":"ok","height":"","hash":"","index":0`)
	}
	fields = append(fields, `"type":"runtime_close","engine_stopped":false`, `"type":"capture_end","dropped":0`)
	var out string
	for i, f := range fields {
		out += row(i, f)
	}
	return out
}
func TestEngineLifecycleKeepsExactParentsAndCandidates(t *testing.T) {
	stages := []string{"start_enter", "subscribed", "handler_enter", "initial_round_return", "start_return", "stop_enter", "timers_stopped", "unsubscribed", "handler_exit", "handler_joined", "stop_return"}
	raw := engineInput(stages)
	c, e := Read(strings.NewReader(raw))
	if e != nil || len(c.Engines) != 1 || c.Engines[0].ID != "18446744073709551615" || c.Engines[0].State != "observed_stopped" || c.RuntimeModelComplete {
		t.Fatal(c, e)
	}
	c, e = Read(strings.NewReader(engineInput(append(stages, "stop_return"))))
	if e != nil || c.Engines[0].State != "ambiguous" || len(c.Engines[0].Stages) != 12 {
		t.Fatal("duplicate chosen", c, e)
	}
	for _, bad := range []string{strings.Replace(raw, `"parent_id":1`, `"parent_id":2`, 1), strings.Replace(raw, `"stage":"handler_exit"`, `"stage":"unknown"`, 1)} {
		if _, e = Read(strings.NewReader(bad)); e == nil {
			t.Fatal("bad relation accepted")
		}
	}
	c, e = Read(strings.NewReader(engineInput(stages[:5])))
	if e != nil || c.Engines[0].State != "observed_started" {
		t.Fatal(c, e)
	}
	c, e = Read(strings.NewReader(strings.Replace(raw, `"parent_id":2,"stage":"stop_enter"`, `"parent_id":0,"stage":"stop_enter"`, 1)))
	if e != nil || c.Engines[0].State != "incomplete" {
		t.Fatal("missing parent inferred", c, e)
	}
	for _, from := range []string{`"t_mono_ns":2`, `"t_mono_ns":3`, `"t_mono_ns":5`, `"t_mono_ns":10`} {
		c, e = Read(strings.NewReader(strings.Replace(raw, from, `"t_mono_ns":0`, 1)))
		if e != nil || c.Engines[0].State == "observed_stopped" {
			t.Fatal("boundary clock repaired", from, c, e)
		}
	}
	c, e = Read(strings.NewReader(strings.Replace(raw, `"t_mono_ns":14`, `"t_mono_ns":0`, 1)))
	if e != nil || c.Engines[0].State == "observed_stopped" {
		t.Fatal("clock repaired", c, e)
	}
}
