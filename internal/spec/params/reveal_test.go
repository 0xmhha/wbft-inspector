package params

import "testing"

func TestBLSRevealActivation(t *testing.T) {
	for _, value := range []string{"null", "3", "18446744073709551619"} {
		cfg, err := ParseGenesis([]byte(`{"config":{"chainId":8282,"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{"rejectNumberJump":0,"blsRandao":` + value + `}}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if (cfg.BLSRandaoAt != nil) != (value != "null") || cfg.BLSRandaoAt != nil && cfg.BLSRandaoAt.String() != value {
			t.Fatal("activation lost precision", value)
		}
	}
	for _, rules := range []string{`"blsRandao":0,"rejectNumberJump":0`, `"blsRandao":3`, `"blsRandao":3,"rejectNumberJump":4`, `"blsRandao":"3","rejectNumberJump":0`, `"blsRandao":1.5,"rejectNumberJump":0`, `"blsRandao":-1,"rejectNumberJump":0`} {
		if _, err := ParseGenesis([]byte(`{"anzeon":{"wbft":{}},"wbftRules":{"consensusRules":{` + rules + `}}}`)); err == nil {
			t.Fatal("invalid activation accepted", rules)
		}
	}
}
