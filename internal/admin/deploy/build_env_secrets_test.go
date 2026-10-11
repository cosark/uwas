package deploy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/apps"
)

type buildSink struct{ b bytes.Buffer }

func (s *buildSink) WriteString(x string) (int, error) { return s.b.WriteString(x) }
func (s *buildSink) Write(p []byte) (int, error)       { return s.b.Write(p) }
func (s *buildSink) String() string                    { return s.b.String() }

// F9210: build commands run tenant repo code; UWAS's own secrets must not reach
// them, while variables the operator configured for the build still do.
func TestBuildCommandEnvExcludesUWASSecrets(t *testing.T) {
	t.Setenv("UWAS_ADMIN_KEY", "SECRET-ADMIN-KEY")
	t.Setenv("CLOUDFLARE_API_TOKEN", "SECRET-CF")
	var sink buildSink
	def := &apps.App{WorkDir: t.TempDir()}
	if err := runAppBuild(context.Background(), def, "printenv", map[string]string{"NPM_TOKEN": "explicit-token"}, &sink); err != nil {
		t.Fatal(err)
	}
	out := sink.String()
	if !strings.Contains(out, "PATH=") {
		t.Error("PATH missing from the build environment")
	}
	for _, leak := range []string{"SECRET-ADMIN-KEY", "SECRET-CF"} {
		if strings.Contains(out, leak) {
			t.Errorf("build environment leaked %q", leak)
		}
	}
	if !strings.Contains(out, "NPM_TOKEN=explicit-token") {
		t.Error("explicitly configured build variable was dropped")
	}
}
