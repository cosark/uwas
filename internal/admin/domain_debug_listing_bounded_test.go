package admin

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F14600: GET /domains/{host}/debug returned the complete top-level listing of
// the docroot, so a tenant that filled its web root with files controlled the
// size and cost of every such response. The listing is now capped.
func TestDomainDebugRootListingIsBounded(t *testing.T) {
	list := func(n int) (files []string, truncated bool) {
		root := t.TempDir()
		for i := 0; i < n; i++ {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%05d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		s := testServerFromConfig(t, &config.Config{
			Global:  config.GlobalConfig{WebRoot: filepath.Dir(root), Admin: config.AdminConfig{Listen: "127.0.0.1:0"}},
			Domains: []config.Domain{{Host: "t.test", Type: "static", Root: root, SSL: config.SSLConfig{Mode: "off"}}},
		})
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/domains/t.test/debug", nil))
		if rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Files     []string `json:"root_files"`
			Truncated bool     `json:"root_files_truncated"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Files, out.Truncated
	}

	files, truncated := list(12)
	if len(files) != 12 || truncated {
		t.Fatalf("small docroot: %d names, truncated=%v; want all 12, not truncated", len(files), truncated)
	}
	if files[0] != "f00000" || files[11] != "f00011" {
		t.Errorf("names are not sorted: %v", files)
	}
	files, truncated = list(debugRootFilesMax + 100)
	if len(files) != debugRootFilesMax || !truncated {
		t.Fatalf("large docroot: %d names, truncated=%v; want %d, truncated", len(files), truncated, debugRootFilesMax)
	}
}
