package logx

import (
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupWritesSlogTextWithComponent(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)
	t.Setenv("ZTX_LOG_LEVEL", "warn")
	var b strings.Builder
	SetupTo(&b, "ztx-test")
	slog.Info("quiet")
	slog.Warn("loud", "n", 3)
	out := b.String()
	if strings.Contains(out, "quiet") {
		t.Errorf("info shown at warn level: %q", out)
	}
	for _, want := range []string{"level=WARN", "msg=loud", "n=3", "component=ztx-test"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

// Logging is slog everywhere: no file of the module imports the standard "log" package.
func TestNoStandardLogImport(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if im.Path.Value == `"log"` {
				t.Errorf("%s imports the standard log package; use log/slog (internal/logx.Setup in a main)", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
