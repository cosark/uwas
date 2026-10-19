package database

// Regression: the explorer's auto-LIMIT guard used substring matching
// (strings.Contains(upper, "LIMIT")), so the word LIMIT inside an identifier —
// a column named `limited_at`, `rate_limit`, … — suppressed the auto-limit and
// the statement ran unbounded, with dbpkg.RunSQL buffering the whole result in
// server memory. The appended " LIMIT n" also shared the statement's line, so
// a trailing "-- comment" swallowed it and the executed statement was again
// unbounded. Both guards now use a word-boundary LIMIT match, and the clause
// is appended on its own line.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubLimitClient puts a fake mariadb client first on PATH; it appends the SQL
// it receives on stdin to a capture file and answers with a minimal TSV, so
// the real handler → dbpkg.RunSQL → client path is exercised end to end.
func stubLimitClient(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat >> " + filepath.Join(dir, "captured.sql") + "\nprintf 'id\\n1\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "mariadb"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(dir, "captured.sql")
}

func runExploreQuery(t *testing.T, sql string, limit int) {
	t.Helper()
	h := New(readonlyTestDeps{})
	body, _ := json.Marshal(map[string]any{"sql": sql, "limit": limit})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/database/explore/shopdb/query", strings.NewReader(string(body)))
	r.SetPathValue("db", "shopdb")
	w := httptest.NewRecorder()
	h.ExploreQuery(w, r)
}

func readCapturedSQL(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the explorer never reached the mysql client")
		}
		t.Fatal(err)
	}
	return string(data)
}

// lastStatementLine returns the last non-empty line the client received; the
// appended LIMIT must be that line, outside any trailing comment.
func lastStatementLine(sql string) string {
	lines := strings.Split(strings.TrimRight(sql, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}

// TestAutoLimitAppliedDespiteSubstringIdentifier: a column whose name contains
// "limit" must not suppress the auto-limit on a plain SELECT.
func TestAutoLimitAppliedDespiteSubstringIdentifier(t *testing.T) {
	capture := stubLimitClient(t)
	runExploreQuery(t, "SELECT id, limited_at FROM logs", 10)

	sql := readCapturedSQL(t, capture)
	if !strings.Contains(lastStatementLine(sql), "LIMIT 10") {
		t.Fatalf("plain SELECT with identifier 'limited_at' ran unbounded — no active auto-LIMIT in:\n%s", sql)
	}
}

// TestAutoLimitSurvivesTrailingLineComment: the appended LIMIT must not land
// inside a trailing "-- comment".
func TestAutoLimitSurvivesTrailingLineComment(t *testing.T) {
	capture := stubLimitClient(t)
	runExploreQuery(t, "SELECT id FROM logs -- note", 10)

	sql := readCapturedSQL(t, capture)
	if got := lastStatementLine(sql); got != "LIMIT 10" {
		t.Fatalf("appended LIMIT swallowed by trailing comment; last line = %q in:\n%s", got, sql)
	}
}

// TestExplicitLimitStillHonored: a statement with its own LIMIT clause is left
// alone by the auto-limit.
func TestExplicitLimitStillHonored(t *testing.T) {
	capture := stubLimitClient(t)
	runExploreQuery(t, "SELECT id FROM logs LIMIT 5", 10)

	sql := readCapturedSQL(t, capture)
	if strings.Count(strings.ToUpper(sql), "LIMIT") != 1 {
		t.Fatalf("explicit LIMIT statement was modified:\n%s", sql)
	}
}
