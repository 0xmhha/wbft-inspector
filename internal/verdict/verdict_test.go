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
		{[]Instance{p}, Pass, ""},
		{[]Instance{p, p}, Pass, ""},
		{[]Instance{p, u}, CannotDecide, PartlyDecided},
		{[]Instance{p, u2, u, p}, CannotDecide, PartlyDecided},
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

// TestPartlyDecided: passed and undecided instances without a failure
// are not a pass; the detail and the coverage keep the three counts apart.
func TestPartlyDecided(t *testing.T) {
	p := Instance{Requirement: "R", Key: "a", Verdict: Pass}
	u := Instance{Requirement: "R", Key: "b", Verdict: CannotDecide, Reason: ClockUncertainty}
	u2 := Instance{Requirement: "R", Key: "c", Verdict: CannotDecide}
	r := Aggregate([]Instance{p, p, p, u, u2})
	if r.Verdict != CannotDecide || r.Reason != PartlyDecided {
		t.Fatalf("%s %s", r.Verdict, r.Reason)
	}
	if r.Pass != 3 || r.Fail != 0 || r.CannotDecide != 2 || r.Reasons[ClockUncertainty] != 1 || r.Reasons[MissingData] != 1 {
		t.Errorf("coverage %+v", r)
	}
	// Ties go to the schema order: MISSING_DATA before CLOCK_UNCERTAINTY.
	want := "3 of 5 instances passed and 2 could not be decided (most often MISSING_DATA); none failed"
	if r.Detail != want {
		t.Errorf("detail %q, want %q", r.Detail, want)
	}
	if len(r.Undecided) != 2 {
		t.Errorf("undecided samples %d", len(r.Undecided))
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
