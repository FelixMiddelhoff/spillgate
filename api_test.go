package spillgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestNoExportedDecodePathWithoutLimits keeps the central promise visible to
// the compiler's friends: no exported function or method can decode data
// without going through Limits. It reads the package source and applies three
// rules to every exported declaration of the non-test files:
//
//   - package-level functions either take a Limits value, or are options
//     (name starts with "With");
//   - methods exist only on Decoder (which carries validated limits), Limits,
//     Kind and *Error;
//   - the exported methods of Decoder are exactly the known four.
//
// A new exported entry point therefore fails this test until a human decides
// it is safe and adds it here.
//
// Covers: SG-R-API-01
func TestNoExportedDecodePathWithoutLimits(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	var decoderMethods []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if fn.Recv == nil {
				requireLimitsOrOption(t, fn)
				continue
			}
			receiver := receiverName(fn)
			if !ast.IsExported(receiver) {
				continue // methods of unexported types are reachable only through interfaces
			}
			switch receiver {
			case "Decoder":
				decoderMethods = append(decoderMethods, fn.Name.Name)
			case "Limits", "Kind", "Error":
			default:
				t.Errorf("exported method %s.%s: receivers are limited to Decoder, Limits, Kind and Error", receiver, fn.Name.Name)
			}
		}
	}

	slices.Sort(decoderMethods)
	want := []string{"ReadAll", "ReadAllContext", "Reader", "ReaderContext"}
	if !slices.Equal(decoderMethods, want) {
		t.Errorf("exported Decoder methods = %v, want %v", decoderMethods, want)
	}
}

func requireLimitsOrOption(t *testing.T, fn *ast.FuncDecl) {
	t.Helper()
	if strings.HasPrefix(fn.Name.Name, "With") {
		return
	}
	for _, param := range fn.Type.Params.List {
		if ident, ok := param.Type.(*ast.Ident); ok && ident.Name == "Limits" {
			return
		}
	}
	t.Errorf("exported function %s neither takes Limits nor is an option", fn.Name.Name)
}

// receiverName returns the type name of a method receiver, without pointer.
func receiverName(fn *ast.FuncDecl) string {
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return "?"
}

// The root module must stay free of dependencies and of unsafe, cgo and
// anything that touches files, processes or the network.
// Covers: SG-I-05
func TestCoreModuleIsStdlibOnlyAndHarmless(t *testing.T) {
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gomod), "require") {
		t.Fatal("the core module must have no dependencies")
	}

	forbidden := []string{`"unsafe"`, `"C"`, `"os"`, `"os/exec"`, `"net"`, `"net/http"`, `"syscall"`, `"plugin"`, `"reflect"`}
	entries, _ := os.ReadDir(".")
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			if slices.Contains(forbidden, imp.Path.Value) {
				t.Errorf("%s imports %s", name, imp.Path.Value)
			}
		}
	}
}
