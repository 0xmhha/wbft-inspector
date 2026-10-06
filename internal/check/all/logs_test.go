package all

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
)

// TestLogReadersUseNoMonotonicTime: a checker that judges runs read from
// logs (check.LogReader) must not read monotonic time, which logs do not
// carry. The test scans the Run method of every checker type of this
// repository for TMono and Timer.Expired.
func TestLogReadersUseNoMonotonicTime(t *testing.T) {
	usesMono := map[string]bool{}
	for _, dir := range []string{"../sm", "../timer", "../net"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range af.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || fd.Name.Name != "Run" {
					continue
				}
				recv := fd.Recv.List[0].Type
				if st, ok := recv.(*ast.StarExpr); ok {
					recv = st.X
				}
				name := recv.(*ast.Ident).Name
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "TMono" || sel.Sel.Name == "Expired" || sel.Sel.Name == "ArmMono") {
						usesMono[name] = true
					}
					return true
				})
			}
		}
	}
	if len(usesMono) == 0 {
		t.Fatal("found no checker that reads monotonic time; the scan is broken")
	}
	readers := 0
	for _, c := range check.All() {
		lr, ok := c.(check.LogReader)
		if !ok || !lr.JudgesLogs() {
			continue
		}
		readers++
		if typ := reflect.TypeOf(c).Name(); usesMono[typ] {
			t.Errorf("checker %s (%s) judges log runs but reads monotonic time", c.Name(), typ)
		}
	}
	if readers == 0 {
		t.Fatal("no checker judges log runs")
	}
}
