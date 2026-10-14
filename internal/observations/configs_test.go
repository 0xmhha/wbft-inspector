package observations

import (
	"encoding/json"
	"strings"
	"testing"
)

func configInput(t *testing.T, duplicate bool) string {
	t.Helper()
	raw := engineInput([]string{"start_enter", "subscribed", "handler_enter", "initial_round_return", "start_return", "stop_enter", "timers_stopped", "unsubscribed", "handler_exit", "handler_joined", "stop_return"})
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var r map[string]any
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if e := d.Decode(&r); e != nil {
			t.Fatal(e)
		}
		rows = append(rows, r)
	}
	out := []map[string]any{}
	for _, r := range rows {
		if r["type"] == "operation_end" && r["id"] == json.Number("1") {
			config := map[string]any{"type": "engine_config", "id": json.Number("18446744073709551615"), "parent_id": 1, "config": rows[0]["config"]}
			out = append(out, config)
			if duplicate {
				out = append(out, config)
			}
		}
		out = append(out, r)
	}
	return configRows(t, out)
}
func configRows(t *testing.T, rows []map[string]any) string {
	t.Helper()
	var out strings.Builder
	for i, r := range rows {
		r["v"] = 1
		r["node"] = "0x1111111111111111111111111111111111111111"
		r["run"] = "synthetic"
		r["seq"] = i
		r["t_mono_ns"] = i
		r["t_wall"] = "2026-01-01T00:00:00Z"
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.String()
}
func TestConfigurationUsesExactInstanceAndKeepsEveryCandidate(t *testing.T) {
	raw := configInput(t, false)
	c, e := Read(strings.NewReader(raw))
	if e != nil || c.Format != "wbft-tap-observations/4" || c.Engines[0].Configuration != "observed" || len(c.Engines[0].Configs) != 1 || c.RuntimeModelComplete {
		t.Fatal(c, e)
	}
	c, e = Read(strings.NewReader(configInput(t, true)))
	if e != nil || c.Engines[0].Configuration != "ambiguous" || len(c.Engines[0].Configs) != 2 {
		t.Fatal("duplicate chosen", c, e)
	}
	for _, bad := range []string{strings.Replace(raw, `"parent_id":1,"run":"synthetic","seq":8`, `"parent_id":2,"run":"synthetic","seq":8`, 1), strings.Replace(raw, `"id":18446744073709551615,"node":"0x1111111111111111111111111111111111111111","parent_id":1,"run":"synthetic","seq":8`, `"id":17,"node":"0x1111111111111111111111111111111111111111","parent_id":1,"run":"synthetic","seq":8`, 1)} {
		if bad == raw {
			t.Fatal("mutation absent")
		}
		if _, e = Read(strings.NewReader(bad)); e == nil {
			t.Fatal("unrelated configuration accepted")
		}
	}
}
func TestLegacyStartupCandidatesAreNotSilentlyDiscarded(t *testing.T) {
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(fixture()), "\n") {
		var r map[string]any
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if e := d.Decode(&r); e != nil {
			t.Fatal(e)
		}
		rows = append(rows, r)
	}
	rows = append(rows[:4], rows[0], rows[4])
	c, e := Read(strings.NewReader(configRows(t, rows)))
	if e != nil || len(c.Startups) != 2 || len(c.Engines) != 0 || c.RuntimeModelComplete {
		t.Fatal(c, e)
	}
}

func TestAmbiguousStartupDoesNotVerifyConfigurationBoundary(t *testing.T) {
	raw := configInput(t, false)
	rows := []map[string]any{}
	var boundary map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var r map[string]any
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if e := d.Decode(&r); e != nil {
			t.Fatal(e)
		}
		if r["stage"] == "start_return" {
			boundary = r
		}
		if r["type"] == "engine_config" {
			rows = append(rows, boundary)
		}
		rows = append(rows, r)
	}
	c, e := Read(strings.NewReader(configRows(t, rows)))
	if e != nil || c.Engines[0].State != "ambiguous" || c.Engines[0].Configuration == "observed" {
		t.Fatal(c, e)
	}
}
