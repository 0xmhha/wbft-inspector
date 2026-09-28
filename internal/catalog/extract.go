package catalog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	chapterFile = regexp.MustCompile(`^([AB]-\d{2})-.*\.md$`)
	reqLine     = regexp.MustCompile(`^\[((?:WBFT|SNET)-[A-Z]+-\d{3})\]\s*(.*)$`)
	metaLine    = regexp.MustCompile(`^(?:- )?(Source|Observable|Observed as):`)
	obsLine     = regexp.MustCompile(`^(?:- )?Observable:\s*(.*)$`)
	mustNot     = regexp.MustCompile(`\bMUST NOT\b`)
	must        = regexp.MustCompile(`\bMUST\b`)
	shouldNot   = regexp.MustCompile(`\bSHOULD NOT\b`)
	should      = regexp.MustCompile(`\bSHOULD\b`)
	may         = regexp.MustCompile(`\bMAY\b`)
)

// Extract reads the requirement definitions of the chapter files
// (A-NN-*.md, B-NN-*.md) of a specification directory. A requirement is a
// line that starts with "[ID]"; its text runs until the first metadata line
// (Source:, Observable:, Observed as:) or the next requirement or heading.
// The level is the strongest RFC 2119 keyword of the text (MUST, MUST NOT,
// SHOULD, SHOULD NOT, MAY, in this order).
func Extract(specDir string) ([]Requirement, error) {
	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && chapterFile.MatchString(e.Name()) {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	seen := map[string]string{}
	var out []Requirement
	for _, name := range files {
		reqs, err := extractFile(filepath.Join(specDir, name), chapterFile.FindStringSubmatch(name)[1])
		if err != nil {
			return nil, err
		}
		for _, r := range reqs {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s: %s is also defined in %s", name, r.ID, prev)
			}
			seen[r.ID] = name
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func extractFile(path, chapter string) ([]Requirement, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var (
		out    []Requirement
		cur    *Requirement
		text   []string
		inBody bool
	)
	flush := func() {
		if cur == nil {
			return
		}
		body := strings.Join(text, "\n")
		cur.Level = level(body)
		cur.Withdrawn = strings.Contains(body, "(withdrawn")
		out = append(out, *cur)
		cur, text = nil, nil
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if m := reqLine.FindStringSubmatch(l); m != nil {
			flush()
			cur = &Requirement{ID: m[1], Chapter: chapter, Tags: []string{}}
			text = []string{m[2]}
			inBody = true
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(l, "#") || l == "---" {
			flush()
			continue
		}
		if m := obsLine.FindStringSubmatch(l); m != nil {
			inBody = false
			for _, t := range strings.Split(m[1], ",") {
				if t = strings.TrimSpace(t); t != "" {
					cur.Tags = append(cur.Tags, t)
				}
			}
			continue
		}
		if metaLine.MatchString(l) {
			inBody = false
			continue
		}
		if inBody {
			text = append(text, l)
		}
	}
	flush()
	return out, sc.Err()
}

// level returns the strongest RFC 2119 keyword of a requirement text.
func level(s string) string {
	plainMust := len(must.FindAllStringIndex(s, -1)) > len(mustNot.FindAllStringIndex(s, -1))
	plainShould := len(should.FindAllStringIndex(s, -1)) > len(shouldNot.FindAllStringIndex(s, -1))
	switch {
	case plainMust:
		return "MUST"
	case mustNot.MatchString(s):
		return "MUST NOT"
	case plainShould:
		return "SHOULD"
	case shouldNot.MatchString(s):
		return "SHOULD NOT"
	case may.MatchString(s):
		return "MAY"
	}
	return ""
}
