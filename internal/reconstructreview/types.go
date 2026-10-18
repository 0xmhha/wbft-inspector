// Package reconstructreview validates source-bound reconstructed comparison
// packets. Packet validation never decides specification conformance.
package reconstructreview

const Format = "wbft-reconstruction-review/1"
const ValidationFormat = "wbft-reconstruction-review-validation/1"
const MaxBytes = 512 << 10

type Network struct {
	ChainID string `json:"chain_id"`
	Genesis string `json:"genesis_hash"`
}
type Height struct {
	Height string   `json:"height"`
	Status string   `json:"status"`
	Issues []string `json:"issues"`
}
type Source struct {
	LogSHA               string   `json:"log_sha256"`
	LogProfile           string   `json:"log_profile"`
	LogProfileSHA        string   `json:"log_profile_sha256"`
	LogNormalizer        string   `json:"log_normalizer"`
	ProcessingSHA        string   `json:"processing_sha256"`
	ProcessingFormat     string   `json:"processing_format"`
	ProcessingNormalizer string   `json:"processing_normalizer"`
	ProcessingRun        string   `json:"processing_run"`
	ProcessingInstance   string   `json:"processing_instance"`
	FrameRun             string   `json:"frame_run"`
	FrameSHA             string   `json:"frame_sha256"`
	ChainSHA             string   `json:"chain_sha256"`
	GenesisSHA           string   `json:"genesis_sha256"`
	BinarySHA            string   `json:"binary_sha256"`
	SourceCommit         string   `json:"source_commit"`
	CaptureComplete      bool     `json:"capture_complete"`
	CaptureIssues        []string `json:"capture_issues"`
}
type Point struct {
	Kind         string `json:"kind"`
	File         string `json:"file"`
	Line         int64  `json:"line,omitempty"`
	BlockIndex   string `json:"block_index,omitempty"`
	Run          string `json:"run,omitempty"`
	Sequence     string `json:"sequence,omitempty"`
	ViewInferred bool   `json:"view_inferred,omitempty"`
}
type Parameters struct {
	RequestTimeoutMS          string `json:"request_timeout_ms"`
	BlockPeriodSeconds        string `json:"block_period_seconds"`
	Epoch                     string `json:"epoch"`
	MaxRequestTimeoutSeconds  string `json:"max_request_timeout_seconds"`
	AllowedFutureBlockSeconds string `json:"allowed_future_block_seconds"`
	ProposerPolicy            string `json:"proposer_policy"`
}
type Projection struct {
	Method          string      `json:"method,omitempty"`
	ArgumentSHA     string      `json:"argument_sha256,omitempty"`
	Running         *bool       `json:"running,omitempty"`
	Valset          string      `json:"valset_digest,omitempty"`
	Parameters      *Parameters `json:"parameters,omitempty"`
	Kind            string      `json:"kind"`
	Code            string      `json:"code,omitempty"`
	Height          string      `json:"height,omitempty"`
	Round           string      `json:"round,omitempty"`
	Digest          string      `json:"digest,omitempty"`
	State           string      `json:"state,omitempty"`
	DurationNS      string      `json:"duration_ns,omitempty"`
	DurationSeconds string      `json:"duration_seconds,omitempty"`
	Timer           string      `json:"timer,omitempty"`
	Proposer        string      `json:"proposer,omitempty"`
	Source          *Point      `json:"source,omitempty"`
}
type Content struct {
	Source     Point  `json:"source"`
	Peer       string `json:"peer"`
	PayloadSHA string `json:"payload_sha256"`
	Digest     string `json:"digest"`
}
type Input struct {
	ContentModel           string   `json:"content_model,omitempty"`
	Via                    string   `json:"via"`
	ProcessingMono         string   `json:"processing_mono_ns,omitempty"`
	Instance               string   `json:"observation_instance,omitempty"`
	DerivedTimerGeneration string   `json:"derived_timer_generation,omitempty"`
	Ordinal                string   `json:"ordinal"`
	Kind                   string   `json:"kind"`
	Height                 string   `json:"height"`
	Round                  string   `json:"round"`
	Source                 Point    `json:"source"`
	Content                *Content `json:"content,omitempty"`
	Head                   *Point   `json:"head,omitempty"`
	Application            *Point   `json:"application,omitempty"`
	TimerArm               *Point   `json:"timer_arm,omitempty"`
	ReceiveClock           string   `json:"receive_clock,omitempty"`
}
type Difference struct {
	Kind     string      `json:"kind"`
	Expected *Projection `json:"expected,omitempty"`
	Actual   *Projection `json:"actual,omitempty"`
}
type Step struct {
	CoreApplied bool         `json:"core_applied"`
	Issues      []string     `json:"issues"`
	Input       Input        `json:"input"`
	Observed    []Projection `json:"observed"`
	Computed    []Projection `json:"computed"`
	Differences []Difference `json:"difference_candidates"`
}
type Packet struct {
	Format               string  `json:"format"`
	Classification       string  `json:"classification"`
	SpecificationVerdict string  `json:"specification_verdict"`
	ResultSHA            string  `json:"result_sha256"`
	ExecutionVersion     string  `json:"execution_version"`
	ComparisonModel      string  `json:"comparison_model"`
	CoreVersion          string  `json:"core_version"`
	AllImprovementsOff   bool    `json:"all_improvements_off"`
	Network              Network `json:"network"`
	Node                 string  `json:"node"`
	Height               Height  `json:"height"`
	LogRun               string  `json:"log_run"`
	Position             int64   `json:"position"`
	Source               Source  `json:"source"`
	Step                 Step    `json:"step"`
}
type Result struct {
	Format                   string `json:"format"`
	PacketSHA                string `json:"packet_sha256"`
	ExpectedChecksumVerified bool   `json:"expected_checksum_verified"`
	ParentResultVerified     bool   `json:"parent_result_verified"`
	SourceTruthVerified      bool   `json:"source_truth_verified"`
	SpecificationVerdict     string `json:"specification_verdict"`
	Packet                   Packet `json:"packet"`
}
