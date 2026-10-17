package frames

import (
	"encoding/json"
	"strings"
	"testing"
)

const syncProcessedJSON = `{"stage":"processed","request":"9007199254740993","operation":"18446744073709551615","syncing":true,"success":false,"first_before":false,"first_after":false,"running_before":true,"running_after":false,"action":"stop","failed":false,"events_available":true,"event_before":"9007199254740993","event_after":"9007199254740995","sequence_exhausted":false,"request_source":{"source_available":true,"source_seq":"9007199254740997","source_segment":"18446744073709551615","source_offset":"9223372036854775807"}}`

func TestSyncControlKeepsFullCountersAndDistinctCoordinateSpaces(t *testing.T) {
	c, err := decodeSyncControl([]byte(syncProcessedJSON))
	if err != nil {
		t.Fatal(err)
	}
	if c.Request != "9007199254740993" || c.Operation != "18446744073709551615" || c.EventBefore != "9007199254740993" || c.EventAfter != "9007199254740995" || c.RequestSource.Seq != "9007199254740997" || c.RequestSource.Offset != "9223372036854775807" {
		t.Fatal("source counters changed", c)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"success":false`) || !strings.Contains(string(raw), `"source_seq":"9007199254740997"`) {
		t.Fatal("explicit false or full source coordinate lost", string(raw))
	}
	// An unavailable source is retained; no coordinate is inferred from the
	// processing identity or canonical-event cursor.
	unlinked := strings.Replace(syncProcessedJSON, `"request_source":{"source_available":true,"source_seq":"9007199254740997","source_segment":"18446744073709551615","source_offset":"9223372036854775807"}`, `"request_source":{"source_available":false}`, 1)
	c, err = decodeSyncControl([]byte(unlinked))
	if err != nil || c.RequestSource.Available == nil || *c.RequestSource.Available || c.RequestSource.Seq != "" {
		t.Fatal("unavailable source changed", c, err)
	}
}

func TestSyncMetadataRejectsMalformedClosedObjects(t *testing.T) {
	for _, replacement := range [][2]string{
		{`"request":"9007199254740993"`, `"request":9007199254740993`},
		{`"request":"9007199254740993"`, `"request":"09007199254740993"`},
		{`"operation":"18446744073709551615"`, `"operation":"18446744073709551616"`},
		{`"event_after":"9007199254740995"`, `"event_after":"9007199254740992"`},
		{`"source_offset":"9223372036854775807"`, `"source_offset":"9223372036854775808"`},
		{`"source_available":true`, `"source_available":false`},
		{`"source_available":true`, `"source_available":null`},
		{`"source_available":true`, `"source_available":true,"source_available":true`},
		{`"source_available":true`, `"source_available":true,"payload":"discard-me"`},
		{`"stage":"processed"`, `"stage":"guessed"`},
		{`"action":"stop"`, `"action":"guessed"`},
		{`"stage":"processed"`, `"stage":"processed","payload":"discard-me"`},
		{`"stage":"processed"`, `"stage":"processed","stage":"processed"`},
	} {
		raw := strings.Replace(syncProcessedJSON, replacement[0], replacement[1], 1)
		if raw == syncProcessedJSON {
			t.Fatal("fixture replacement did not apply")
		}
		if _, err := decodeSyncControl([]byte(raw)); err == nil {
			t.Fatal("malformed sync source accepted", raw)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(syncProcessedJSON), &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stage", "request", "operation", "syncing", "success", "first_before", "first_after", "running_before", "running_after", "action", "failed", "events_available", "event_before", "event_after", "sequence_exhausted", "request_source"} {
		for _, missing := range []bool{false, true} {
			copyFields := map[string]json.RawMessage{}
			for k, v := range fields {
				copyFields[k] = v
			}
			if missing {
				delete(copyFields, name)
			} else {
				copyFields[name] = json.RawMessage(`null`)
			}
			raw, err := json.Marshal(copyFields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSyncControl(raw); err == nil {
				t.Fatalf("missing/null %s accepted", name)
			}
		}
	}
}

func TestSyncTraceKeepsIncompleteAndRejectsWrongCursorSemantics(t *testing.T) {
	raw := `{"version":"1","requests":"2","operations":"1","complete":false,"event_cursor":"next_sequence"}`
	trace, err := decodeSyncTrace([]byte(raw))
	if err != nil || trace.Complete == nil || *trace.Complete {
		t.Fatal("incomplete source hidden", trace, err)
	}
	for _, bad := range []string{
		strings.Replace(raw, `"version":"1"`, `"version":"2"`, 1),
		strings.Replace(raw, `"complete":false`, `"complete":null`, 1),
		strings.Replace(raw, `"next_sequence"`, `"last_sequence"`, 1),
		strings.Replace(raw, `"requests":"2"`, `"requests":"2.0"`, 1),
		strings.Replace(raw, `"complete":false`, `"complete":false,"private_context":"discard-me"`, 1),
	} {
		if _, err := decodeSyncTrace([]byte(bad)); err == nil {
			t.Fatal("malformed trace accepted", bad)
		}
	}
}
