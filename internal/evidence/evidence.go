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
	// Frame evidence: the record ("<run>:<seq>"), direction, peer, code
	// and payload hash of a frame dump record.
	FrameID       string `json:"frame_id,omitempty"`
	Direction     string `json:"direction,omitempty"`
	Peer          string `json:"peer,omitempty"`
	Code          string `json:"code,omitempty"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
}

// Kinds of evidence used by this build.
const (
	KindEvent    = "event"
	KindFrame    = "frame"
	KindVector   = "vector"
	KindComputed = "computed"
	KindConfig   = "config"
)
