package htaccess

import "testing"

// F16901: LimitRequestBody was parsed by nothing, so a tenant who capped request
// bodies in .htaccess had no cap.
func TestLimitRequestBodyIsRecorded(t *testing.T) {
	for _, c := range []struct {
		src  string
		want int64 // -1 = not set
	}{
		{"LimitRequestBody 100\n", 100},
		{"limitrequestbody 2097152\n", 2097152},
		{"LIMITREQUESTBODY 0\n", 0}, // explicit "unlimited"
		{"# none\n", -1},
		{"LimitRequestBody -5\n", -1},
		{"LimitRequestBody ten\n", -1},
		{"LimitRequestBody\n", -1},
		{"LimitRequestBody 1.5\n", -1},
		{"<IfModule mod_php7.c>\nLimitRequestBody 10\n</IfModule>\n", -1},    // module not loaded
		{"<IfModule mod_headers.c>\nLimitRequestBody 10\n</IfModule>\n", 10}, // loaded
		{"<IfModule !mod_headers.c>\nLimitRequestBody 10\n</IfModule>\n", -1},
	} {
		rs := convertString(t, c.src)
		switch {
		case c.want < 0 && rs.LimitRequestBody != nil:
			t.Errorf("%q: recorded %d, want not set", c.src, *rs.LimitRequestBody)
		case c.want >= 0 && (rs.LimitRequestBody == nil || *rs.LimitRequestBody != c.want):
			t.Errorf("%q: got %v, want %d", c.src, rs.LimitRequestBody, c.want)
		}
	}
}

// A cap in a section whose condition cannot be decided only ever restricts, so
// it is kept; a "0" there would lift a cap, so it is not.
func TestLimitRequestBodyInUndecidedSection(t *testing.T) {
	rs := convertString(t, "<If \"%{HTTP_HOST} == 'a'\">\nLimitRequestBody 50\n</If>\n")
	if rs.LimitRequestBody == nil || *rs.LimitRequestBody != 50 {
		t.Errorf("cap in an undecidable <If> dropped: %v", rs.LimitRequestBody)
	}
	rs = convertString(t, "LimitRequestBody 50\n<If \"%{HTTP_HOST} == 'a'\">\nLimitRequestBody 0\n</If>\n")
	if rs.LimitRequestBody == nil || *rs.LimitRequestBody != 50 {
		t.Errorf("an undecidable section lifted the cap: %v", rs.LimitRequestBody)
	}
}

func TestLimitRequestBodyForDeepestLevelWins(t *testing.T) {
	cap100 := convertString(t, "LimitRequestBody 100\n")
	lift := convertString(t, "LimitRequestBody 0\n")
	cap7 := convertString(t, "LimitRequestBody 7\n")
	none := convertString(t, "# nothing\n")

	for _, c := range []struct {
		name  string
		chain []*RuleSet
		want  int64
	}{
		{"no levels", nil, 0},
		{"no level says anything", []*RuleSet{none, nil, none}, 0},
		{"parent cap reaches the child", []*RuleSet{cap100, none}, 100},
		{"child tightens", []*RuleSet{cap100, cap7}, 7},
		{"child lifts with 0", []*RuleSet{cap100, lift}, 0},
		{"child re-caps after a lift", []*RuleSet{cap100, lift, cap7}, 7},
		{"nil levels are skipped", []*RuleSet{nil, cap100, nil}, 100},
	} {
		if got := LimitRequestBodyFor(c.chain); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestLimitRequestBodyMerge(t *testing.T) {
	a := convertString(t, "LimitRequestBody 100\n")
	a.Merge(convertString(t, "# nothing\n"))
	if a.LimitRequestBody == nil || *a.LimitRequestBody != 100 {
		t.Fatalf("a level that says nothing changed the cap: %v", a.LimitRequestBody)
	}
	a.Merge(convertString(t, "LimitRequestBody 9\n"))
	if *a.LimitRequestBody != 9 {
		t.Errorf("merged cap = %d, want 9", *a.LimitRequestBody)
	}
}
