// Package yamlsubset parses the YAML subset of the WBFT conformance vectors
// (wbft-spec A-11, WBFT-VEC-013) and rejects every file outside it.
//
// The subset converts to JSON one to one: block mappings and block sequences
// indented by two spaces, keys made of a-z, 0-9 and _, double-quoted strings
// with JSON escaping, true, false, null, and the empty collections [] and {}.
// A general YAML parser would accept more (comments, plain scalars, numbers,
// anchors, flow collections); this parser reports those as errors instead of
// interpreting them. The rules follow the specification's reference checker
// (spec/tools/vectorgen/check_yaml_subset.py) line by line.
//
// Parsed values are map[string]any, []any, string, bool and nil.
package yamlsubset

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Error is a violation of the subset, with the 1-based line when known.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

var (
	keyRe      = regexp.MustCompile(`^[a-z0-9_]+$`)
	keyLineRe  = regexp.MustCompile(`^([^:\s]+):(?: (.*))?$`)
	itemMapRe  = regexp.MustCompile(`^[^:\s"]+:(?: |$)`)
	hexRe      = regexp.MustCompile(`^0x(?:[0-9a-f]{2})*$`)
	errMapping = "the document is not a mapping at indentation 0"
)

type line struct {
	indent  int
	content string
	no      int
}

type parser struct {
	lines []line
	pos   int
}

// Parse parses one vector file. The document must be a mapping.
func Parse(text []byte) (map[string]any, error) {
	s := string(text)
	if strings.HasPrefix(s, "\uFEFF") {
		return nil, &Error{Msg: "byte order mark"}
	}
	if strings.Contains(s, "\r") {
		return nil, &Error{Msg: "CR character (use LF line ends)"}
	}
	if !strings.HasSuffix(s, "\n") {
		return nil, &Error{Msg: "no final newline"}
	}
	p := &parser{}
	for i, raw := range strings.Split(s[:len(s)-1], "\n") {
		no := i + 1
		if strings.Contains(raw, "\t") {
			return nil, &Error{no, "tab character"}
		}
		if strings.TrimSpace(raw) == "" {
			return nil, &Error{no, "blank line"}
		}
		if raw != strings.TrimRight(raw, " ") {
			return nil, &Error{no, "trailing space"}
		}
		content := strings.TrimLeft(raw, " ")
		indent := len(raw) - len(content)
		if indent%2 != 0 {
			return nil, &Error{no, "indentation is not a multiple of two spaces"}
		}
		p.lines = append(p.lines, line{indent, content, no})
	}
	if len(p.lines) == 0 {
		return nil, &Error{Msg: "empty document"}
	}
	first := p.lines[0]
	if first.indent != 0 || strings.HasPrefix(first.content, "-") {
		return nil, &Error{Msg: errMapping}
	}
	doc, err := p.parseMap(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		return nil, &Error{p.lines[p.pos].no, "unexpected indentation"}
	}
	return doc, nil
}

func (p *parser) peek() *line {
	if p.pos < len(p.lines) {
		return &p.lines[p.pos]
	}
	return nil
}

func isItem(content string) bool { return content == "-" || strings.HasPrefix(content, "- ") }

func (p *parser) parseBlock(indent, no int) (any, error) {
	next := p.peek()
	if next == nil || next.indent != indent {
		return nil, &Error{no, "empty block (write [] or {}) or wrong indentation"}
	}
	if isItem(next.content) {
		return p.parseSeq(indent)
	}
	return p.parseMap(indent)
}

func (p *parser) parseMap(indent int) (map[string]any, error) {
	out := map[string]any{}
	for {
		cur := p.peek()
		if cur == nil || cur.indent < indent {
			return out, nil
		}
		if cur.indent > indent {
			return nil, &Error{cur.no, "unexpected indentation"}
		}
		if isItem(cur.content) {
			return nil, &Error{cur.no, "sequence item inside a mapping"}
		}
		idx := keyLineRe.FindStringSubmatchIndex(cur.content)
		if idx == nil {
			return nil, &Error{cur.no, "not a 'key: value' or 'key:' line"}
		}
		key := cur.content[idx[2]:idx[3]]
		hasValue := idx[4] >= 0
		if !keyRe.MatchString(key) {
			return nil, &Error{cur.no, fmt.Sprintf("key %q is not [a-z0-9_]+ (quoted keys are not in the subset)", key)}
		}
		if _, dup := out[key]; dup {
			return nil, &Error{cur.no, fmt.Sprintf("duplicate key %q", key)}
		}
		no := cur.no
		p.pos++
		if !hasValue {
			v, err := p.parseBlock(indent+2, no)
			if err != nil {
				return nil, err
			}
			out[key] = v
			continue
		}
		val := cur.content[idx[4]:idx[5]]
		v, ok, err := parseScalar(val, no)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, &Error{no, fmt.Sprintf("value %q is not a double-quoted string, true, false, null, [] or {}", clip(val))}
		}
		out[key] = v
	}
}

func (p *parser) parseSeq(indent int) ([]any, error) {
	out := []any{}
	for {
		cur := p.peek()
		if cur == nil || cur.indent < indent {
			return out, nil
		}
		if cur.indent > indent {
			return nil, &Error{cur.no, "unexpected indentation"}
		}
		switch {
		case cur.content == "-":
			no := cur.no
			p.pos++
			v, err := p.parseBlock(indent+2, no)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case strings.HasPrefix(cur.content, "- "):
			rest := cur.content[2:]
			v, ok, err := parseScalar(rest, cur.no)
			if err != nil {
				return nil, err
			}
			if ok {
				p.pos++
				out = append(out, v)
				continue
			}
			if itemMapRe.MatchString(rest) {
				// "- key: ..." starts a mapping item whose keys are aligned
				// two columns to the right.
				cur.indent, cur.content = indent+2, rest
				m, err := p.parseMap(indent + 2)
				if err != nil {
					return nil, err
				}
				out = append(out, m)
				continue
			}
			return nil, &Error{cur.no, fmt.Sprintf("item %q is not an allowed scalar or mapping", clip(rest))}
		default:
			return nil, &Error{cur.no, "mapping key inside a sequence"}
		}
	}
}

// parseScalar returns the value of an allowed scalar token and true, or
// false when the token is not a scalar of the subset.
func parseScalar(tok string, no int) (any, bool, error) {
	switch tok {
	case "true":
		return true, true, nil
	case "false":
		return false, true, nil
	case "null":
		return nil, true, nil
	case "[]":
		return []any{}, true, nil
	case "{}":
		return map[string]any{}, true, nil
	}
	if strings.HasPrefix(tok, `"`) {
		var v any
		if err := json.Unmarshal([]byte(tok), &v); err != nil {
			return nil, false, &Error{no, "malformed double-quoted string"}
		}
		s, ok := v.(string)
		if !ok {
			return nil, false, &Error{no, "not a string"}
		}
		return s, true, nil
	}
	return nil, false, nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// CheckValues reports byte strings that are not lowercase hexadecimal of
// even length (WBFT-VEC-014). where names the file in the messages.
func CheckValues(v any, where string) []string {
	var out []string
	var walk func(any, string)
	walk = func(v any, at string) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], at+"."+k)
			}
		case []any:
			for i, y := range x {
				walk(y, fmt.Sprintf("%s[%d]", at, i))
			}
		case string:
			if strings.HasPrefix(x, "0x") && !hexRe.MatchString(x) {
				out = append(out, fmt.Sprintf("%s: byte string %q is not lowercase even-length hex (WBFT-VEC-014)", at, clip(x)))
			}
		}
	}
	walk(v, where)
	return out
}
