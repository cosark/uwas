package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// pagedAPI answers the list endpoints the way the admin API does: an envelope
// {"items","total","limit","offset"}, limit defaulting to 50 and capped at 500
// (internal/admin parsePagination / paginateSlice).
func pagedAPI(t *testing.T, domains, php int) *httptest.Server {
	t.Helper()
	page := func(w http.ResponseWriter, r *http.Request, total int, item func(i int) map[string]any) {
		limit, offset := 50, 0
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
			limit = n
		}
		if limit > 500 {
			limit = 500
		}
		if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n >= 0 {
			offset = n
		}
		items := []map[string]any{}
		for i := offset; i < total && i < offset+limit; i++ {
			items = append(items, item(i))
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/domains", func(w http.ResponseWriter, r *http.Request) {
		page(w, r, domains, func(i int) map[string]any {
			return map[string]any{"host": fmt.Sprintf("site%03d.example", i), "type": "static", "ssl": "off", "root": "/var/www"}
		})
	})
	mux.HandleFunc("/api/v1/php", func(w http.ResponseWriter, r *http.Request) {
		page(w, r, php, func(i int) map[string]any {
			return map[string]any{"version": fmt.Sprintf("7.%d", i), "sapi": "fpm", "binary": "/usr/bin/php"}
		})
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "uptime": "1h"})
	})
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"requests_total": 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// F14304: the list endpoints are paginated (50 per page by default). domain
// list, php list and status read the first page only, so a server with more
// than 50 domains was listed (and counted by "status") as having 50.
func TestListCommandsReadEveryPage(t *testing.T) {
	srv := pagedAPI(t, 120, 60)

	var err error
	out := captureStdout(t, func() { err = (&DomainCommand{}).Run([]string{"list", "--api-url", srv.URL}) })
	if err != nil {
		t.Fatalf("domain list: %v", err)
	}
	if got := strings.Count(out, ".example"); got != 120 {
		t.Errorf("domain list printed %d of 120 domains", got)
	}

	out = captureStdout(t, func() { err = (&StatusCommand{}).Run([]string{"--api-url", srv.URL}) })
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "Domains:      120") {
		t.Errorf("status did not count all 120 domains:\n%s", firstLines(out, 12))
	}

	out = captureStdout(t, func() { err = (&PHPCommand{}).Run([]string{"list", "--api-url", srv.URL}) })
	if err != nil {
		t.Fatalf("php list: %v", err)
	}
	if got := strings.Count(out, "fpm"); got != 60 {
		t.Errorf("php list printed %d of 60 installations", got)
	}
}

// A short list is unchanged, and a server that ignores offset (an older
// release) must not make the CLI repeat the first page.
func TestListCommandsShortListAndOffsetIgnoringServer(t *testing.T) {
	srv := pagedAPI(t, 3, 0)
	var err error
	out := captureStdout(t, func() { err = (&DomainCommand{}).Run([]string{"list", "--api-url", srv.URL}) })
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, ".example"); got != 3 {
		t.Errorf("3-domain list printed %d rows", got)
	}

	ignoring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items := []map[string]any{}
		for i := 0; i < 50; i++ {
			items = append(items, map[string]any{"host": fmt.Sprintf("old%02d.example", i), "type": "static"})
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": 120})
	}))
	t.Cleanup(ignoring.Close)
	out = captureStdout(t, func() { err = (&DomainCommand{}).Run([]string{"list", "--api-url", ignoring.URL}) })
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, ".example"); got != 50 {
		t.Errorf("offset-ignoring server: printed %d rows, want the 50 it returned once", got)
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
