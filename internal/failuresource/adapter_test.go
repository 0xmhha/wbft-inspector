package failuresource

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is a JSON contract model, not a runtime or failed-signature capture.
func modelResult() Result {
	return Result{Status: "consistent", Scope: scope, PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", Caches: "1", Operations: "8", VerifiedFailures: "1", Stored: "1", LookupHits: "2", ConsumedFailures: "2", Retained: "1", Inbox: Inbox{Status: "consistent", Scope: "inbox_queue_worker_snapshot_slot_and_core_input_sources", PhysicalStatus: "unavailable", ScheduleStatus: "unavailable", Appended: "4", Dequeued: "4", Checked: "2", CachedFailures: "2", Taken: "1", Dispatched: "1", DiscardedKnown: "0", Clears: "0", RetainedQueued: "0", RetainedChecking: "0", RetainedSlots: "0", RetainedTaken: "0"}}
}
func TestReceiveFailureReportContractPreservesSeparateCounts(t *testing.T) {
	for _, outcome := range []struct {
		status string
		exit   int
	}{{"consistent", 0}, {"unavailable", 69}, {"inconsistent", 1}} {
		r := modelResult()
		r.Status = outcome.status
		if outcome.exit != 0 {
			r.Reason = "source_unavailable_or_contradictory"
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(raw, outcome.exit)
		if err != nil || got != r || got.Inbox.Checked != "2" || got.ConsumedFailures != "2" {
			t.Fatal("report counts/status changed", got, err)
		}
		if _, err := Decode(raw, 70); err == nil {
			t.Fatal("exit/status mismatch accepted")
		}
	}
	raw, err := json.Marshal(modelResult())
	if err != nil {
		t.Fatal(err)
	}
	invalid := [][]byte{[]byte(`null`), []byte(`{}`), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Replace(raw, []byte(`"status":"consistent"`), []byte(`"status":"consistent","status":"unavailable"`), 1), bytes.Replace(raw, []byte(`"checked":"2"`), []byte(`"checked":2`), 1), bytes.Replace(raw, []byte(`"checked":"2"`), []byte(`"checked":"02"`), 1), bytes.Replace(raw, []byte(`"verified_failures":"1"`), []byte(`"verified_failures":"18446744073709551616"`), 1), bytes.Replace(raw, []byte(`"scope":`), []byte(`"unexpected":`), 1), bytes.Replace(raw, []byte(`"physical_status":"unavailable"`), []byte(`"physical_status":"consistent"`), 1), bytes.Repeat([]byte{' '}, MaxResultBytes+1)}
	for i, input := range invalid {
		if _, err := Decode(input, 0); err == nil {
			t.Fatal("invalid checker report accepted", i)
		}
	}
}
func TestReceiveFailureAdapterRejectsUnselectedExecutable(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	binary := filepath.Join(t.TempDir(), "unselected-checker")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(t.Context(), binary, strings.Repeat("0", 64), "source", "limits", time.Second); err == nil {
		t.Fatal("non-WBFT executable accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unselected program executed", err)
	}
	var output boundedOutput
	if _, err := output.Write(make([]byte, MaxResultBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{1}); err == nil || output.Len() != MaxResultBytes {
		t.Fatal("output limit not enforced")
	}
}

func TestReceiveFailureFingerprintBindsAllOriginalFiles(t *testing.T) {
	directory := t.TempDir()
	segment := filepath.Join(directory, "00000000000000000001.wal")
	if err := os.WriteFile(segment, []byte("metadata fingerprint fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := fingerprint(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(segment, []byte("different metadata fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := fingerprint(t.Context(), directory)
	if err != nil || before == after {
		t.Fatal("source bytes not bound", err)
	}
	if err = os.Symlink(segment, filepath.Join(directory, "00000000000000000002.wal")); err != nil {
		t.Fatal(err)
	}
	if _, err = fingerprint(t.Context(), directory); err == nil {
		t.Fatal("linked source accepted")
	}
}

func TestReceiveFailureNestedInboxContract(t *testing.T) {
	for _, status := range []string{"consistent", "unavailable", "inconsistent"} {
		code := 0
		if status == "unavailable" {
			code = 69
		}
		if status == "inconsistent" {
			code = 1
		}
		baseline := modelResult()
		baseline.Status = status
		if code != 0 {
			baseline.Reason = "source_missing"
		}
		for _, change := range []func(*Inbox){func(i *Inbox) { i.Scope = "different_scope" }, func(i *Inbox) { i.Status = "unknown" }, func(i *Inbox) { i.Reason = "unexpected_reason" }, func(i *Inbox) { i.PhysicalStatus = "consistent" }, func(i *Inbox) { i.ScheduleStatus = "consistent" }, func(i *Inbox) { i.Status = "" }} {
			r := baseline
			change(&r.Inbox)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Decode(raw, code); err == nil {
				t.Fatal("invalid nested inbox accepted", status, r.Inbox)
			}
		}
	}
	r := modelResult()
	r.Status = "unavailable"
	r.Reason = "core_source_missing"
	r.Inbox = Inbox{Appended: "0", Dequeued: "0", Checked: "0", Taken: "0", Dispatched: "0", DiscardedKnown: "0", Clears: "0", RetainedQueued: "0", RetainedChecking: "0", RetainedSlots: "0", RetainedTaken: "0"}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw, 69); err != nil {
		t.Fatal("valid early default inbox refused", err)
	}
	r.Inbox.Checked = "1"
	raw, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw, 69); err == nil {
		t.Fatal("nondefault inbox escaped as empty")
	}
}
