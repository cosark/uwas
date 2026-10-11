package config

import "strings"

// SecurityConfig is the per-domain security policy: blocked paths, WAF,
// rate limiting, IP allow/deny lists, geo blocking.
type SecurityConfig struct {
	BlockedPaths      []string        `yaml:"blocked_paths,omitempty" json:"blocked_paths,omitempty"`
	HotlinkProtection HotlinkConfig   `yaml:"hotlink_protection,omitempty" json:"hotlink_protection,omitempty"`
	RateLimit         RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	WAF               WAFConfig       `yaml:"waf,omitempty" json:"waf,omitempty"`
	CloudflareOnly    bool            `yaml:"cloudflare_only,omitempty" json:"cloudflare_only,omitempty"`
	IPWhitelist       []string        `yaml:"ip_whitelist,omitempty" json:"ip_whitelist,omitempty"`
	IPBlacklist       []string        `yaml:"ip_blacklist,omitempty" json:"ip_blacklist,omitempty"`
	GeoBlockCountries []string        `yaml:"geo_block_countries,omitempty" json:"geo_block_countries,omitempty"` // 2-letter ISO codes
	GeoAllowCountries []string        `yaml:"geo_allow_countries,omitempty" json:"geo_allow_countries,omitempty"` // whitelist mode
}

// HotlinkConfig controls hotlink protection (referer-based image blocking).
type HotlinkConfig struct {
	Enabled         bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	AllowedReferers []string `yaml:"allowed_referers,omitempty" json:"allowed_referers,omitempty"`
	Extensions      []string `yaml:"extensions,omitempty" json:"extensions,omitempty"`
}

// RateLimitConfig configures token-bucket rate limiting. Used globally
// (GlobalConfig.RateLimit), per-domain (SecurityConfig.RateLimit), and
// per-location (LocationConfig.RateLimit).
type RateLimitConfig struct {
	Requests int      `yaml:"requests,omitempty" json:"requests,omitempty"`
	Window   Duration `yaml:"window,omitempty" json:"window,omitempty"`
	By       string   `yaml:"by,omitempty" json:"by,omitempty"`
}

// WAFConfig configures the web application firewall.
type WAFConfig struct {
	Enabled     bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	BypassPaths []string `yaml:"bypass_paths,omitempty" json:"bypass_paths,omitempty"` // skip WAF for these path prefixes
	Rules       []string `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// wafRuleNames are the families security.waf.rules may name. They mirror the
// families internal/middleware defines (a test in internal/server keeps the
// two lists in step), which config cannot import.
var wafRuleNames = []string{"sql_injection", "xss", "path_traversal", "shell_injection", "php", "file_probe"}

// KnownWAFRuleName reports whether name is one of the WAF families, matched
// the way the WAF matches it (case-insensitive, surrounding space ignored).
func KnownWAFRuleName(name string) bool {
	name = strings.TrimSpace(name)
	for _, f := range wafRuleNames {
		if strings.EqualFold(name, f) {
			return true
		}
	}
	return false
}

// WAFRuleNames returns the family names security.waf.rules accepts.
func WAFRuleNames() []string {
	return append([]string(nil), wafRuleNames...)
}
