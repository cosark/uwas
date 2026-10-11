package rewrite

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// F11200: a rewrite that runs before the file is resolved (the YAML rewrites)
// gets no resolved path; REQUEST_FILENAME must then be the document root plus
// the cleaned request path, or every "-f" test fails and "!-f" matches files
// that exist.
func TestBuildVariablesDefaultsRequestFilename(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "uploads"), 0o755)
	os.WriteFile(filepath.Join(root, "uploads", "a.php"), []byte("x"), 0o644)

	req := httptest.NewRequest("GET", "/uploads/a.php", nil)
	v := BuildVariables(req, root, "", false)
	if want := filepath.Join(root, "uploads", "a.php"); v.RequestFilename != want {
		t.Fatalf("RequestFilename = %q, want %q", v.RequestFilename, want)
	}

	isFile, _ := ParseCondition("%{REQUEST_FILENAME}", "-f", "")
	notFile, _ := ParseCondition("%{REQUEST_FILENAME}", "!-f", "")
	if ok, _ := isFile.Evaluate(v); !ok {
		t.Error("-f on an existing file did not match")
	}
	if ok, _ := notFile.Evaluate(v); ok {
		t.Error("!-f on an existing file matched")
	}

	// A missing file: -f false, !-f true (control).
	miss := BuildVariables(httptest.NewRequest("GET", "/uploads/none.php", nil), root, "", false)
	if ok, _ := isFile.Evaluate(miss); ok {
		t.Error("-f on a missing file matched")
	}
	if ok, _ := notFile.Evaluate(miss); !ok {
		t.Error("!-f on a missing file did not match")
	}

	// Traversal stays inside the root; ".." cannot name a file above it.
	esc := BuildVariables(httptest.NewRequest("GET", "/uploads/../../etc/passwd", nil), root, "", false)
	if want := filepath.Join(root, "etc", "passwd"); esc.RequestFilename != want {
		t.Errorf("traversal RequestFilename = %q, want %q", esc.RequestFilename, want)
	}

	// An explicit resolved path wins; no document root leaves it empty.
	if got := BuildVariables(req, root, "/x/y", false).RequestFilename; got != "/x/y" {
		t.Errorf("explicit path replaced: %q", got)
	}
	if got := BuildVariables(req, "", "", false).RequestFilename; got != "" {
		t.Errorf("no root: RequestFilename = %q, want empty", got)
	}
}
