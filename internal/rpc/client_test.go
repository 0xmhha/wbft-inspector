package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBatchIDs(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		bad            bool
	}{
		{"reordered", `[{"jsonrpc":"2.0","id":2,"result":"second"},{"jsonrpc":"2.0","id":1,"result":"first"}]`, false},
		{"duplicate", `[{"jsonrpc":"2.0","id":1,"result":1},{"jsonrpc":"2.0","id":1,"result":2}]`, true},
		{"missing", `[{"jsonrpc":"2.0","id":1,"result":1}]`, true},
		{"foreign", `[{"jsonrpc":"2.0","id":3,"result":1}]`, true},
		{"bad protocol", `[{"jsonrpc":"1.0","id":1,"result":1}]`, true},
		{"both answer forms", `[{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":-1}}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.response)) }))
			defer server.Close()
			c, _ := New(server.URL, 5)
			a, err := c.Batch(context.Background(), []Request{{Method: "a"}, {Method: "b"}})
			if (err != nil) != tc.bad {
				t.Fatalf("answers=%v error=%v", a, err)
			}
			if !tc.bad && (string(a[0].Result) != `"first"` || string(a[1].Result) != `"second"`) {
				t.Fatal(a)
			}
		})
	}
}
func TestCallErrorsAndProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`[{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unavailable"}}]`))
	}))
	defer server.Close()
	c, _ := New(server.URL, 5)
	c.Interval = 0
	var out string
	if err := c.Call(context.Background(), &out, "unknown"); err == nil || !strings.Contains(err.Error(), "-32601") {
		t.Fatal(err)
	}
	if available, err := c.Probe(context.Background(), "unknown"); err != nil || available {
		t.Fatal(available, err)
	}
	if _, err := c.Batch(context.Background(), make([]Request, 101)); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	if _, err := New(server.URL, 6); err == nil {
		t.Fatal("rate bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.next = time.Now().Add(time.Hour)
	if _, err := c.Batch(ctx, []Request{{Method: "x"}}); err != context.Canceled {
		t.Fatal(err)
	}
}
