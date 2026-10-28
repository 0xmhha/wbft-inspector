// Package failuresource consumes an explicitly selected original-source checker.
// It does not decide conformance or project failure hits into legacy events.
package failuresource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxResultBytes = 1 << 20
const scope = "original_failure_checks_bounded_cache_and_inbox_consumption"

var ErrAdapter = errors.New("original source checker unavailable or invalid")

type Result struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Scope            string `json:"scope"`
	PhysicalStatus   string `json:"physical_status"`
	ScheduleStatus   string `json:"schedule_status"`
	Caches           string `json:"caches"`
	Operations       string `json:"operations"`
	VerifiedFailures string `json:"verified_failures"`
	Stored           string `json:"stored"`
	LookupHits       string `json:"lookup_hits"`
	ConsumedFailures string `json:"consumed_failures"`
	Retained         string `json:"retained"`
	Inbox            Inbox  `json:"inbox"`
}
type Inbox struct {
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Scope            string `json:"scope"`
	PhysicalStatus   string `json:"physical_status"`
	ScheduleStatus   string `json:"schedule_status"`
	Appended         string `json:"appended"`
	Dequeued         string `json:"dequeued"`
	Checked          string `json:"checked"`
	CachedFailures   string `json:"cached_failures,omitempty"`
	Taken            string `json:"taken"`
	Dispatched       string `json:"dispatched"`
	DiscardedKnown   string `json:"discarded_known"`
	Clears           string `json:"clears"`
	RetainedQueued   string `json:"retained_queued"`
	RetainedChecking string `json:"retained_checking"`
	RetainedSlots    string `json:"retained_slots"`
	RetainedTaken    string `json:"retained_taken"`
}

// Decode validates the current source-report contract and its command outcome.
// Physical or schedule certification is outside this conditional source API.
func Decode(raw []byte, exit int) (Result, error) {
	var r Result
	if len(raw) == 0 || len(raw) > MaxResultBytes {
		return r, ErrAdapter
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if uniqueValue(d, 0) != nil {
		return r, ErrAdapter
	}
	if _, err := d.Token(); err != io.EOF {
		return r, ErrAdapter
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return r, ErrAdapter
	}
	if r.Scope != scope || r.PhysicalStatus != "unavailable" || r.ScheduleStatus != "unavailable" {
		return r, ErrAdapter
	}
	expected := 69
	switch r.Status {
	case "consistent":
		expected = 0
	case "unavailable":
	case "inconsistent":
		expected = 1
	default:
		return r, ErrAdapter
	}
	if expected != exit || r.Status == "consistent" && r.Reason != "" || r.Status != "consistent" && r.Reason == "" {
		return r, ErrAdapter
	}
	for _, n := range []string{r.Caches, r.Operations, r.VerifiedFailures, r.Stored, r.LookupHits, r.ConsumedFailures, r.Retained, r.Inbox.Appended, r.Inbox.Dequeued, r.Inbox.Checked, r.Inbox.Taken, r.Inbox.Dispatched, r.Inbox.DiscardedKnown, r.Inbox.Clears, r.Inbox.RetainedQueued, r.Inbox.RetainedChecking, r.Inbox.RetainedSlots, r.Inbox.RetainedTaken} {
		if !decimal(n) {
			return r, ErrAdapter
		}
	}
	if r.Inbox.CachedFailures != "" && !decimal(r.Inbox.CachedFailures) {
		return r, ErrAdapter
	}
	// Early unavailable/contradiction reports may have only a default inbox.
	if r.Inbox.Status == "" {
		zero := Inbox{Appended: "0", Dequeued: "0", Checked: "0", Taken: "0", Dispatched: "0", DiscardedKnown: "0", Clears: "0", RetainedQueued: "0", RetainedChecking: "0", RetainedSlots: "0", RetainedTaken: "0"}
		if r.Status == "consistent" || r.Inbox != zero {
			return r, ErrAdapter
		}
	} else {
		if r.Inbox.Scope != "inbox_queue_worker_snapshot_slot_and_core_input_sources" || r.Inbox.PhysicalStatus != "unavailable" || r.Inbox.ScheduleStatus != "unavailable" {
			return r, ErrAdapter
		}
		switch r.Inbox.Status {
		case "consistent":
			if r.Inbox.Reason != "" {
				return r, ErrAdapter
			}
		case "unavailable", "inconsistent":
			if r.Inbox.Reason == "" {
				return r, ErrAdapter
			}
		default:
			return r, ErrAdapter
		}
		if r.Status == "consistent" && r.Inbox.Status != "consistent" {
			return r, ErrAdapter
		}
	}

	return r, nil
}
func decimal(s string) bool {
	n, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == s
}
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrAdapter
	}
	t, err := d.Token()
	if err != nil {
		return ErrAdapter
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			key, ok := k.(string)
			if err != nil || !ok || key != strings.ToLower(key) || seen[key] {
				return ErrAdapter
			}
			seen[key] = true
			if uniqueValue(d, depth+1) != nil {
				return ErrAdapter
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrAdapter
		}
	case json.Delim('['):
		for d.More() {
			if uniqueValue(d, depth+1) != nil {
				return ErrAdapter
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrAdapter
		}
	}
	return nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > MaxResultBytes-b.Len() {
		return 0, ErrAdapter
	}
	return b.Buffer.Write(p)
}

// Check invokes only the explicit, hash-matched WBFT journal checker. Its
// report remains implementation source evidence, not an inspector verdict.
// A hash identifies the selected executable; it is not a trust endorsement.
func Check(ctx context.Context, binary, digest, directory, limits string, timeout time.Duration) (Result, error) {
	var empty Result
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !filepath.IsAbs(binary) || len(digest) != 64 || timeout <= 0 || timeout > 10*time.Minute {
		return empty, ErrAdapter
	}
	wanted, err := hex.DecodeString(digest)
	if err != nil {
		return empty, ErrAdapter
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return empty, ErrAdapter
	}
	identity, err := buildinfo.ReadFile(binary)
	if err != nil || identity.Path != "github.com/0xmhha/wbft/cmd/wbft-journal" {
		return empty, ErrAdapter
	}
	hashFile := func() bool {
		f, err := os.Open(binary)
		if err != nil {
			return false
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			return false
		}
		return bytes.Equal(h.Sum(nil), wanted)
	}
	if !hashFile() {
		return empty, ErrAdapter
	}
	before, err := fingerprint(ctx, directory)
	if err != nil {
		return empty, ErrAdapter
	}
	command := exec.CommandContext(ctx, binary, "check-receive-failures", "--dir", directory, "--source-limits", limits) //nolint:gosec // explicit hash-matched user selection
	command.WaitDelay = time.Second
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	err = command.Run()
	if ctx.Err() != nil {
		return empty, ErrAdapter
	}
	code := 0
	if err != nil {
		var status *exec.ExitError
		if !errors.As(err, &status) {
			return empty, ErrAdapter
		}
		code = status.ExitCode()
	}
	if !hashFile() {
		return empty, ErrAdapter
	}
	after, err := fingerprint(ctx, directory)
	if err != nil || before != after {
		return empty, ErrAdapter
	}
	return Decode(output.Bytes(), code)
}

var journalName = regexp.MustCompile(`^[0-9]{20}\.wal(\.idx)?$`)

// Fingerprint refuses links and unexpected files and binds all reader-visible
// segment/index bytes. It adds no event projection or execution interpretation.
func fingerprint(ctx context.Context, directory string) ([32]byte, error) {
	var empty [32]byte
	root, err := os.OpenRoot(directory)
	if err != nil {
		return empty, ErrAdapter
	}
	defer root.Close()
	h := sha256.New()
	files := 0
	segments := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return ErrAdapter
		}
		if name == "." {
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() || !journalName.MatchString(name) || files >= 100000 {
			return ErrAdapter
		}
		f, err := root.Open(name)
		if err != nil {
			return ErrAdapter
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
			return ErrAdapter
		}
		digest := sha256.New()
		var size int64
		buffer := make([]byte, 64<<10)
		for {
			if ctx.Err() != nil {
				return ErrAdapter
			}
			n, e := f.Read(buffer)
			if n > 0 {
				_, _ = digest.Write(buffer[:n])
				size += int64(n)
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return ErrAdapter
			}
		}
		if size != info.Size() {
			return ErrAdapter
		}
		_, _ = fmt.Fprintf(h, "%s:%d:%x\n", name, size, digest.Sum(nil))
		files++
		if strings.HasSuffix(name, ".wal") {
			segments++
		}
		return nil
	})
	if err != nil || segments == 0 {
		return empty, ErrAdapter
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}
