package params

import (
	"math/big"
	"testing"
)

func u(v uint64) *uint64 { return &v }

// The worked example of wbft-spec A-01 §6.6.
func TestConfigAtWorkedExample(t *testing.T) {
	raw := []byte(`{"config":{"anzeon":{"wbft":{"requestTimeoutSeconds":2,"blockPeriodSeconds":1,"epochLength":10,"proposerPolicy":0}},
	"transitions":[{"block":200,"blockPeriodSeconds":2,"maxRequestTimeoutSeconds":30},
	               {"block":100,"epochLength":20,"requestTimeoutSeconds":0,"proposerPolicy":1},
	               {"block":300,"maxRequestTimeoutSeconds":0}]}}`)
	c, err := ParseGenesis(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		n                   int64
		rt, bp, epoch, capS uint64
		policy              uint64
	}{
		{0, 2000, 1, 10, 0, 0},
		{99, 2000, 1, 10, 0, 0},
		{100, 2000, 1, 20, 0, 1},
		{200, 2000, 2, 20, 30, 1},
		{299, 2000, 2, 20, 30, 1},
		{300, 2000, 2, 20, 0, 1},
	}
	for _, x := range cases {
		r := c.At(big.NewInt(x.n))
		if r.RequestTimeoutMs != x.rt || r.BlockPeriodSeconds != x.bp || r.Epoch != x.epoch || r.MaxRequestTimeoutSeconds != x.capS || r.ProposerPolicy == nil || *r.ProposerPolicy != x.policy {
			t.Errorf("config_at(%d) = %+v (policy %v)", x.n, r, r.ProposerPolicy)
		}
	}
}

func TestRequestTimeoutWraps(t *testing.T) {
	c, err := New(WBFT{RequestTimeoutSeconds: 18446744073709552, ProposerPolicy: u(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.At(big.NewInt(1)).RequestTimeoutMs; got != 384 {
		t.Fatalf("got %d, want 384 (uint64 wrap)", got)
	}
}

func TestParseErrors(t *testing.T) {
	for _, raw := range []string{`{}`, `{"anzeon":{}}`, `{"anzeon":{"wbft":{"requestTimeoutSeconds":-1}}}`,
		`{"anzeon":{"wbft":{}},"transitions":[{"requestTimeoutSeconds":1}]}`} {
		if _, err := ParseGenesis([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}
