package router

import (
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// F12600: browsers send the punycode form of an internationalized host, so a
// host or alias configured in Unicode must still match it (and vice versa).
func TestRouterMatchesUnicodeAndPunycodeSpellings(t *testing.T) {
	uni := config.Domain{Host: "bücher.example", Aliases: []string{"*.bücher.example"}, Type: "static", Root: "/u"}
	ascii := config.Domain{Host: "plain.example", Type: "static", Root: "/p"}
	r := NewVHostRouter([]config.Domain{ascii, uni})

	for _, host := range []string{
		"xn--bcher-kva.example", "XN--BCHER-KVA.example.", "bücher.example",
		"shop.xn--bcher-kva.example", "shop.bücher.example",
	} {
		d, ok := r.LookupWithStatus(host)
		if !ok || d == nil || d.Host != "bücher.example" {
			t.Errorf("Lookup(%q) configured=%v, want the bücher.example domain", host, ok)
		}
	}
	// Control: other hosts are unaffected and an unknown IDN falls back.
	if d, ok := r.LookupWithStatus("PLAIN.example"); !ok || d.Host != "plain.example" {
		t.Errorf("ascii control: configured=%v", ok)
	}
	if _, ok := r.LookupWithStatus("xn--mnchen-3ya.example"); ok {
		t.Error("unrelated IDN host must not match")
	}
}

// A Unicode alias that spells another domain's punycode host is reported by
// Validate, so the router never has to pick a winner between them.
func TestRouterPortQualifiedUnicodeHost(t *testing.T) {
	d := config.Domain{Host: "bücher.example:8080", Type: "static", Root: "/u"}
	r := NewVHostRouter([]config.Domain{d})
	if got, ok := r.LookupWithStatus("xn--bcher-kva.example:8080"); !ok || got.Host != d.Host {
		t.Errorf("port-qualified punycode lookup: configured=%v", ok)
	}
}
