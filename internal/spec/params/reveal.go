package params

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// parseBLSRandao reads only the rule needed to select the reveal profile.
// Other rule names retain their existing independent observer handling.
func parseBLSRandao(raw []byte) (*big.Int, error) {
	var cfg struct {
		Rules struct {
			Consensus map[string]json.RawMessage `json:"consensusRules"`
		} `json:"wbftRules"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	read := func(name string) (*big.Int, error) {
		value, present := cfg.Rules.Consensus[name]
		text := strings.TrimSpace(string(value))
		if !present || text == "null" {
			return nil, nil
		}
		if text == "" || strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return nil, fmt.Errorf("params: %s activation must be a non-negative JSON integer or null", name)
		}
		n, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return nil, fmt.Errorf("params: invalid %s activation", name)
		}
		return n, nil
	}
	at, err := read("blsRandao")
	if err != nil || at == nil {
		return at, err
	}
	if at.Sign() == 0 {
		return nil, fmt.Errorf("params: blsRandao activation must be positive")
	}
	number, err := read("rejectNumberJump")
	if err != nil {
		return nil, err
	}
	if number == nil || number.Cmp(at) > 0 {
		return nil, fmt.Errorf("params: blsRandao requires rejectNumberJump at or before activation")
	}
	return at, nil
}
