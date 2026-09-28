// Package evidence defines the evidence pointers of a report. Evidence points
// at the input (an input id and a line, a block number and hash, a vector
// case) instead of copying it, so that reports stay small and do not carry
// payloads found in node output.
package evidence

// Pointer is one piece of evidence. Kind is required; the other fields
// depend on the kind (report schema, "$defs/evidence").
type Pointer struct {
	Kind       string `json:"kind"`
	Input      string `json:"input,omitempty"`
	Node       string `json:"node,omitempty"`
	Number     string `json:"number,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Field      string `json:"field,omitempty"`
	Line       int    `json:"line,omitempty"`
	T          string `json:"t,omitempty"`
	Msg        string `json:"msg,omitempty"`
	VectorPath string `json:"vector_path,omitempty"`
	Name       string `json:"name,omitempty"`
	Value      string `json:"value,omitempty"`
}

// Kinds of evidence used by this build.
const (
	KindEvent    = "event"
	KindVector   = "vector"
	KindComputed = "computed"
	KindConfig   = "config"
)
