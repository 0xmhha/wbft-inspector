package verdict

import "testing"

func TestAggregate(t *testing.T) {
	p := Instance{Requirement: "R", Key: "a", Verdict: Pass}
	f := Instance{Requirement: "R", Key: "b", Verdict: Fail, Message: "bad"}
	u := Instance{Requirement: "R", Key: "c", Verdict: CannotDecide, Reason: ClockUncertainty, Message: "band"}
	u2 := Instance{Requirement: "R", Key: "d", Verdict: CannotDecide, Reason: ObserverScope}
	cases := []struct {
		in     []Instance
		want   Verdict
		reason Reason
	}{
		{nil, CannotDecide, NotExercised},
		{[]Instance{p, u}, Pass, ""},
		{[]Instance{p, u, f}, Fail, ""},
		{[]Instance{u, u2, u}, CannotDecide, ClockUncertainty},
	}
	for i, c := range cases {
		r := Aggregate(c.in)
		if r.Verdict != c.want || r.Reason != c.reason {
			t.Errorf("case %d: %s %s, want %s %s", i, r.Verdict, r.Reason, c.want, c.reason)
		}
	}
	r := Aggregate([]Instance{p, u, f})
	if r.Instances != 3 || r.Pass != 1 || r.Fail != 1 || r.CannotDecide != 1 || r.Reasons[ClockUncertainty] != 1 || len(r.Violations) != 1 {
		t.Errorf("coverage %+v", r)
	}
}

func TestViolationsAreCapped(t *testing.T) {
	var in []Instance
	for i := 0; i < MaxViolations+5; i++ {
		in = append(in, Instance{Key: string(rune('a' + i%26)), Verdict: Fail})
	}
	r := Aggregate(in)
	if len(r.Violations) != MaxViolations || r.ViolationsTruncated != 5 {
		t.Fatalf("%d kept, %d truncated", len(r.Violations), r.ViolationsTruncated)
	}
}
