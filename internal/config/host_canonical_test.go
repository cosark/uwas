package config

import (
	"strings"
	"testing"
)

// F12600: a Unicode host and its punycode form are one site.
func TestCanonicalHost(t *testing.T) {
	for in, want := range map[string]string{
		"Shop.Example":          "shop.example",      // control: ASCII
		"shop.example.":         "shop.example",      // absolute-form dot
		" shop.example ":        "shop.example",      // surrounding space
		"*.shop.example":        "*.shop.example",    // wildcard kept
		"shop.example:8080":     "shop.example:8080", // port kept
		"[::1]:8080":            "[::1]:8080",        // IPv6 literal untouched
		"bücher.example":        "xn--bcher-kva.example",
		"BÜCHER.Example.":       "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"*.bücher.example":      "*.xn--bcher-kva.example",
		"bücher.example:8443":   "xn--bcher-kva.example:8443",
		"www.bücher.example":    "www.xn--bcher-kva.example",
		"a\u200db.example":      "a\u200db.example", // IDNA rejects it: unchanged (lower-cased)
	} {
		if got := CanonicalHost(in); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateDuplicateAcrossIDNSpellings(t *testing.T) {
	mk := func(a, b config_pair) *Config {
		return &Config{Domains: []Domain{
			{Host: a.host, Type: "static", Root: "/a", Aliases: a.aliases},
			{Host: b.host, Type: "static", Root: "/b", Aliases: b.aliases},
		}}
	}
	cases := map[string]*Config{
		"alias vs punycode host":         mk(config_pair{host: "xn--bcher-kva.example"}, config_pair{host: "other.example", aliases: []string{"bücher.example"}}),
		"unicode host vs punycode alias": mk(config_pair{host: "bücher.example"}, config_pair{host: "other.example", aliases: []string{"xn--bcher-kva.example"}}),
		"two spellings as hosts":         mk(config_pair{host: "bücher.example"}, config_pair{host: "xn--bcher-kva.example"}),
	}
	for name, cfg := range cases {
		err := ValidateWithDefaults(cfg)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("%s: err = %v, want a duplicate error", name, err)
		}
	}
	// Control: unrelated hosts are fine.
	ok := mk(config_pair{host: "bücher.example"}, config_pair{host: "other.example", aliases: []string{"bar.example"}})
	if err := ValidateWithDefaults(ok); err != nil {
		t.Errorf("control: unexpected error %v", err)
	}
}

type config_pair struct {
	host    string
	aliases []string
}
