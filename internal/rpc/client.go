// Package rpc reads a node with bounded, rate-limited JSON-RPC batches.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type Request struct {
	Method string
	Params []any
}
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("RPC %d: %s", e.Code, e.Message) }

type Answer struct {
	Result json.RawMessage
	Error  *Error
}
type Client struct {
	URL      string
	HTTP     *http.Client
	Interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func New(url string, rate float64) (*Client, error) {
	if rate <= 0 || rate > 5 {
		return nil, errors.New("RPC rate must be in (0, 5]")
	}
	return &Client{URL: url, HTTP: &http.Client{Timeout: 30 * time.Second}, Interval: time.Duration(float64(time.Second) / rate)}, nil
}

// Batch matches replies by ID, including out-of-order responses. Transport,
// throttling and server failures are retried; JSON-RPC errors remain per item.
func (c *Client) Batch(ctx context.Context, requests []Request) ([]Answer, error) {
	if len(requests) == 0 || len(requests) > 100 {
		return nil, errors.New("RPC batch must contain 1..100 requests")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	body := make([]map[string]any, len(requests))
	for i, r := range requests {
		p := r.Params
		if p == nil {
			p = []any{}
		}
		body[i] = map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": r.Method, "params": p}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		delay := time.Until(c.next)
		if attempt > 0 && delay < time.Duration(attempt)*time.Second {
			delay = time.Duration(attempt) * time.Second
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		c.next = time.Now().Add(c.Interval)
		req, err := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
		_ = response.Body.Close()
		if response.StatusCode != 200 {
			last = fmt.Errorf("RPC HTTP %d", response.StatusCode)
			if response.StatusCode == 429 || response.StatusCode >= 500 {
				continue
			}
			return nil, last
		}
		if readErr != nil {
			last = readErr
			continue
		}
		if len(data) > 32<<20 {
			return nil, errors.New("RPC response exceeds 32 MiB")
		}
		var replies []struct {
			Version string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *Error          `json:"error"`
		}
		if err = json.Unmarshal(data, &replies); err != nil {
			return nil, fmt.Errorf("RPC batch response: %w", err)
		}
		out := make([]Answer, len(requests))
		seen := make([]bool, len(requests))
		for _, r := range replies {
			if r.Version != "2.0" || r.ID < 1 || r.ID > len(out) || seen[r.ID-1] || (r.Error == nil && len(r.Result) == 0) || (r.Error != nil && len(r.Result) > 0) {
				return nil, errors.New("RPC invalid or duplicate response ID")
			}
			seen[r.ID-1] = true
			out[r.ID-1] = Answer{r.Result, r.Error}
		}
		for _, v := range seen {
			if !v {
				return nil, errors.New("RPC missing response ID")
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("RPC retries exhausted: %w", last)
}
func (c *Client) Call(ctx context.Context, out any, method string, params ...any) error {
	a, err := c.Batch(ctx, []Request{{method, params}})
	if err != nil {
		return err
	}
	if a[0].Error != nil {
		return a[0].Error
	}
	return json.Unmarshal(a[0].Result, out)
}

// Probe reports availability without treating a method error as a transport failure.
func (c *Client) Probe(ctx context.Context, method string, params ...any) (bool, error) {
	a, err := c.Batch(ctx, []Request{{method, params}})
	if err != nil {
		return false, err
	}
	return a[0].Error == nil, nil
}
