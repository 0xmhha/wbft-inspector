package frames

import (
	"testing"
)

func TestIOIntervalValidationRetainsClockRegressionAndAbsence(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{"start_wall": "2026-10-14T00:00:00.000000100Z", "end_wall": "2026-10-14T00:00:00.000000090Z", "start_mono_ns": 0, "end_mono_ns": 1}
	}
	for _, tc := range []struct {
		name  string
		value any
		good  bool
	}{
		{"measured_zero_and_wall_regression", valid(), true}, {"null", nil, false}, {"boolean", true, false}, {"missing", map[string]any{"start_mono_ns": 0}, false}, {"reversed", map[string]any{"start_wall": "2026-10-14T00:00:00Z", "end_wall": "2026-10-14T00:00:00Z", "start_mono_ns": 2, "end_mono_ns": 1}, false}, {"after_callback", map[string]any{"start_wall": "2026-10-14T00:00:00Z", "end_wall": "2026-10-14T00:00:00Z", "start_mono_ns": 0, "end_mono_ns": 3}, false}, {"unknown_field", map[string]any{"start_wall": "2026-10-14T00:00:00Z", "end_wall": "2026-10-14T00:00:00Z", "start_mono_ns": 0, "end_mono_ns": 1, "corrected": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t)
			editLines(t, dir, first(func(r map[string]any) bool { return r["type"] == "frame" }, func(r map[string]any) { r["t_mono_ns"] = 2; r["io"] = tc.value }))
			d, e := Load(dir)
			if e != nil {
				t.Fatal(e)
			}
			if (len(Validate(d).Problems) == 0) != tc.good {
				t.Fatal(Validate(d).Problems)
			}
		})
	}
	d, e := Load(fixture)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range d.Records {
		if r.IO != nil {
			t.Fatal("legacy timestamp became an interval")
		}
	}
}
