package backup

import "testing"

// Regression: matchCronTerm reads numbers with parseInt, which skips every
// non-digit. "0 3 * * mon" therefore validated and fired on Sunday (mon -> 0),
// and "abc * * * *" validated as minute 0. The schedule validator now refuses
// any field that holds characters other than digits and "*,-/".
func TestCronRejectsNonNumericTokens(t *testing.T) {
	for _, ok := range []string{"0 3 * * 1", "*/5 * * * *", "1-5,30 * * * *", "0 3 * * 7", "59-0 * * * *", "0-30/10 * * * *", "* * * * *", "*/5,10-20/2 * * * *", "0 0 13 * 5"} {
		if !ValidCronExpression(ok) {
			t.Errorf("well-formed %q rejected", ok)
		}
	}
	for _, in := range []string{"abc * * * *", "0 3 * * mon", "5x * * * *", "1,x * * * *", "0 3 * * 1a", "0 0 1 jan *", "0 3 * * MON-FRI"} {
		if ValidCronExpression(in) || !nextCronRun(in).IsZero() {
			t.Errorf("%q accepted", in)
		}
	}
}
