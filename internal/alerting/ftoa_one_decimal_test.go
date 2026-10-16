package alerting

import "testing"

// ftoa must print the value to one decimal place; truncating the binary float
// showed 111 errors of 1000 (11.1%) as "11.0" in the error_spike alert (F22101).
func TestFtoaOneDecimal(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{11.1, "11.1"},
		{4.1, "4.1"},
		{14.2, "14.2"},
		{33.3, "33.3"},
		{12.5, "12.5"},
		{0, "0.0"},
		{50, "50.0"},
		{100, "100.0"},
		{-3.7, "-3.7"},
	}
	for _, tc := range cases {
		if got := ftoa(tc.in); got != tc.want {
			t.Errorf("ftoa(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Exact one-decimal percentages the spike alert can produce.
	for e := 1; e <= 999; e++ {
		pct := float64(e) / 1000 * 100
		want := itoa(e/10) + "." + itoa(e%10)
		if got := ftoa(pct); got != want {
			t.Fatalf("ftoa(%d/1000*100 = %v) = %q, want %q", e, pct, got, want)
		}
	}
}
