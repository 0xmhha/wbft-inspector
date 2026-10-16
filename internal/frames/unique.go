package frames

import (
	"bytes"
	"encoding/json"
)

func uniqueFields(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	token, err = d.Token()
	return err == nil && token == json.Delim('}')
}
