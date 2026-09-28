// Package buildinfo names the build of the inspector. The public build knows
// only the public specification; another build (for example one compiled
// with additional packages through go build -overlay) sets its own name from
// an init function, so that every report says which build wrote it.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"sync"
)

// Version is the inspector version; release builds set it with
// -ldflags "-X github.com/0xmhha/wbft-inspector/internal/buildinfo.Version=...".
var Version = "0.1.0-dev"

// Public is the name of the build of this repository.
const Public = "public"

var (
	mu    sync.Mutex
	build = Public
)

// Build returns the build name written to run.inspector.build.
func Build() string {
	mu.Lock()
	defer mu.Unlock()
	return build
}

// SetBuild changes the build name. It is meant for init functions of
// packages that extend the inspector.
func SetBuild(name string) {
	mu.Lock()
	defer mu.Unlock()
	build = name
}

// Commit returns the VCS revision the binary was built from, with a
// "-dirty" suffix for a modified tree, or "unknown".
func Commit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// Go returns the Go version of the binary.
func Go() string { return runtime.Version() }
