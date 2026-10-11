package cache

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func esiIncludes(path string, n int) []byte {
	var b strings.Builder
	b.WriteString("<!--esi ")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `<esi:include src="%s"/>`, path)
	}
	b.WriteString(" -->")
	return []byte(b.String())
}

// F14404: the include allowance is for the whole page, nested fragments
// included. Counted per body, 50 includes of a fragment of 50 includes of a
// fragment of 50 includes (the depth limit is 3) assembled 125,000 leaf copies:
// a 120 MiB response from one cheap request.
func TestESIIncludeAllowanceIsPerPage(t *testing.T) {
	leaf := strings.Repeat("L", 1000)
	p := newTestESIProcessor(map[string][]byte{
		"/f1":   esiIncludes("/f2", 50),
		"/f2":   esiIncludes("/leaf", 50),
		"/leaf": []byte(leaf),
	})
	req := httptest.NewRequest("GET", "/", nil)
	out, err := p.Process(esiIncludes("/f1", 50), "h", req, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), leaf); n > ESIMaxIncludes {
		t.Errorf("page assembled %d leaf copies, want at most %d (the allowance is per page)", n, ESIMaxIncludes)
	}
	if !strings.Contains(string(out), "max includes exceeded") {
		t.Error("the page ran out of its allowance without saying so")
	}
	if len(out) > ESIMaxOutputBytes {
		t.Errorf("assembled %d bytes, over the %d byte limit", len(out), ESIMaxOutputBytes)
	}
}

// A page within its allowance is assembled exactly as before.
func TestESINestedPageWithinAllowanceIsComplete(t *testing.T) {
	p := newTestESIProcessor(map[string][]byte{
		"/outer": []byte(`<div><!--esi <esi:include src="/inner"/><esi:include src="/inner"/> --></div>`),
		"/inner": []byte("I"),
	})
	req := httptest.NewRequest("GET", "/", nil)
	out, err := p.Process([]byte(`<body><!--esi <esi:include src="/outer"/><esi:include src="/outer"/> --></body>`), "h", req, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "<body><div>II</div><div>II</div></body>"; string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// Large fragments cannot be pulled in without bound either: the bytes a page
// adds are capped, and the include that would pass the cap is replaced.
func TestESIOutputBytesAreBounded(t *testing.T) {
	big := strings.Repeat("B", ESIMaxOutputBytes/3+1) // three copies do not fit, two do
	p := newTestESIProcessor(map[string][]byte{"/big": []byte(big)})
	req := httptest.NewRequest("GET", "/", nil)
	out, err := p.Process(esiIncludes("/big", 10), "h", req, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), big); n != 2 {
		t.Errorf("assembled %d copies of a %d byte fragment, want 2 within the %d byte limit", n, len(big), ESIMaxOutputBytes)
	}
	if !strings.Contains(string(out), "ESI error: /big") {
		t.Error("includes past the byte limit were not reported")
	}
}
