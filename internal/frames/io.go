package frames

import (
	"bytes"
	"encoding/json"
	"time"
)

// IOInterval retains endpoints measured with the recording node's clock.
// Missing intervals and wall-clock regressions are never filled or corrected.
type IOInterval struct {
	StartWall string `json:"start_wall"`
	EndWall   string `json:"end_wall"`
	StartMono *int64 `json:"start_mono_ns"`
	EndMono   *int64 `json:"end_mono_ns"`
}

func (x *IOInterval) UnmarshalJSON(raw []byte) error {
	type plain IOInterval
	var value plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	*x = IOInterval(value)
	return nil
}

func validateIO(r *Record, add func(*Record, string, ...any)) {
	x := r.IO
	if r.Type != "frame" || x == nil || x.StartMono == nil || x.EndMono == nil {
		add(r, "io requires a frame and all measured endpoints")
		return
	}
	if *x.StartMono < 0 || *x.EndMono < *x.StartMono || *x.EndMono > r.TMono {
		add(r, "io monotonic interval is outside the recording clock")
	}
	if _, err := time.Parse(tWallLayout, x.StartWall); err != nil {
		add(r, "io start_wall is not RFC 3339")
	}
	if _, err := time.Parse(tWallLayout, x.EndWall); err != nil {
		add(r, "io end_wall is not RFC 3339")
	}
	if r.Dir == "out" && r.WriteResult == "not_attached" {
		add(r, "unattempted write cannot contain io endpoints")
	}
}
