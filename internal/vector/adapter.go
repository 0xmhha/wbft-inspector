package vector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// Protocol is the adapter protocol name.
const Protocol = "wbft-vector/1"

// Hello is the adapter's hello (WBFT-VEC-038).
type Hello struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Impl     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Lang    string `json:"lang"`
		Build   string `json:"build"`
	} `json:"impl"`
	Handlers     []string `json:"handlers"`
	Improvements []string `json:"improvements"`
}

// ErrProtocolName is returned when the adapter speaks another protocol
// (WBFT-VEC-039); the runner reports a usage error.
var ErrProtocolName = errors.New("vector: the adapter speaks another protocol")

// reply is one line of the adapter or the end of its output.
type reply struct {
	line []byte
	err  error
}

// adapter is one adapter process.
type adapter struct {
	cmd   []string
	proc  *exec.Cmd
	stdin io.WriteCloser
	lines chan reply
	done  chan struct{}
	hello Hello
}

// ExitTimeout is how long an adapter may take to exit after bye
// (WBFT-VEC-046).
const ExitTimeout = 5 * time.Second

// helloTimeout bounds the start of an adapter.
const helloTimeout = 30 * time.Second

func startAdapter(cmd []string, runner map[string]string, specCommit string) (*adapter, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("vector: empty adapter command")
	}
	p := exec.Command(cmd[0], cmd[1:]...) //nolint:gosec // the user names the adapter command
	stdin, err := p.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := p.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// Standard error is diagnostics of the adapter; the runner does not
	// interpret it (WBFT-VEC-035).
	p.Stderr = io.Discard
	if err := p.Start(); err != nil {
		return nil, err
	}
	a := &adapter{cmd: cmd, proc: p, stdin: stdin, lines: make(chan reply, 1), done: make(chan struct{})}
	go func() {
		defer close(a.lines)
		br := bufio.NewReaderSize(stdout, 1<<20)
		for {
			// ReadBytes has no line limit, so lines of 64 MiB and more are
			// accepted (WBFT-VEC-036).
			l, err := br.ReadBytes('\n')
			r := reply{line: l}
			if err != nil {
				r = reply{err: err}
			}
			select {
			case a.lines <- r:
			case <-a.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	if err := a.send(map[string]any{"type": "hello", "protocol": Protocol, "runner": runner, "spec_commit": specCommit}); err != nil {
		a.kill()
		return nil, err
	}
	raw, err := a.recv(helloTimeout)
	if err != nil {
		a.kill()
		return nil, fmt.Errorf("vector: no hello from %v: %w", cmd, err)
	}
	if err := json.Unmarshal(raw, &a.hello); err != nil || a.hello.Type != "hello" {
		a.kill()
		return nil, fmt.Errorf("vector: bad hello from %v: %s", cmd, clip(raw))
	}
	if a.hello.Protocol != Protocol {
		a.kill()
		return nil, fmt.Errorf("%w: %q", ErrProtocolName, a.hello.Protocol)
	}
	return a, nil
}

func (a *adapter) send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = a.stdin.Write(append(b, '\n'))
	return err
}

var errTimeout = errors.New("time limit exceeded")

func (a *adapter) recv(limit time.Duration) ([]byte, error) {
	t := time.NewTimer(limit)
	defer t.Stop()
	select {
	case r, ok := <-a.lines:
		if !ok {
			return nil, io.EOF
		}
		return r.line, r.err
	case <-t.C:
		return nil, errTimeout
	}
}

// answer is the adapter's result for one case.
type answer struct {
	Status     string          `json:"status"`
	Output     json.RawMessage `json:"output"`
	ErrorClass string          `json:"error_class"`
	Message    string          `json:"message"`
}

// failure kinds of an exchange.
const (
	exchOK = iota
	exchExited
	exchTimeout
	exchProtocol
)

// do sends one case and waits for its result.
func (a *adapter) do(id int, c *Case, limit time.Duration) (answer, int, string) {
	msg := map[string]any{"type": "case", "id": id, "runner": c.Runner, "handler": c.Handler, "case": c.Name, "kind": c.Kind, "input": c.Input}
	if err := a.send(msg); err != nil {
		return answer{}, exchExited, "write: " + err.Error()
	}
	raw, err := a.recv(limit)
	switch {
	case errors.Is(err, errTimeout):
		return answer{}, exchTimeout, fmt.Sprintf("no result within %s", limit)
	case err != nil:
		return answer{}, exchExited, "adapter exited: " + err.Error()
	}
	var env struct {
		Type string          `json:"type"`
		ID   json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return answer{}, exchProtocol, "not a JSON object: " + clip(raw)
	}
	if env.Type != "result" || string(env.ID) != fmt.Sprint(id) {
		return answer{}, exchProtocol, fmt.Sprintf("expected result %d, got %s", id, clip(raw))
	}
	var ans answer
	if err := json.Unmarshal(raw, &ans); err != nil {
		return answer{}, exchProtocol, "malformed result: " + clip(raw)
	}
	switch ans.Status {
	case "ok", "error", "unsupported":
	default:
		return answer{}, exchProtocol, "unknown status " + ans.Status
	}
	return ans, exchOK, ""
}

// close ends the session with bye and waits for the adapter to exit.
func (a *adapter) close() {
	defer close(a.done)
	_ = a.send(map[string]string{"type": "bye"})
	_ = a.stdin.Close()
	done := make(chan struct{})
	go func() { _ = a.proc.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(ExitTimeout):
		_ = a.proc.Process.Kill()
		<-done
	}
}

// kill terminates the adapter at once (after a crash, a timeout or a
// protocol error, WBFT-VEC-052).
func (a *adapter) kill() {
	defer close(a.done)
	_ = a.stdin.Close()
	_ = a.proc.Process.Kill()
	_ = a.proc.Wait()
}

func clip(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
