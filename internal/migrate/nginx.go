// Package migrate converts third-party web server configs to UWAS domain YAML.
package migrate

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/uwaserver/uwas/internal/config"
)

// NginxConfig holds parsed data from a single Nginx server block.
type NginxConfig struct {
	ServerNames []string // from server_name directive
	Root        string
	ListenPorts []string // raw listen values: "80", "443 ssl", etc.
	SSLCert     string
	SSLKey      string
	IndexFiles  []string
	Locations   []NginxLocation
	ProxyPass   string // server-level proxy_pass
	Return      string // server-level return directive (e.g. "301 https://example.com$request_uri")
	TryFiles    []string
	// Warnings lists access-control directives the converter cannot express;
	// they are dropped from the output, so the operator must be told (F8900).
	Warnings []string
}

// NginxLocation holds parsed data from a location block.
type NginxLocation struct {
	Path      string
	Modifier  string // ~, ~*, =, or empty
	ProxyPass string
	FastCGI   string // fastcgi_pass value
	TryFiles  []string
	Return    string
	DenyAll   bool // "deny all;" - the path must not be served
	Warnings  []string
}

// ParseNginx reads Nginx config from a reader and returns parsed server blocks.
// This is a pragmatic line-by-line parser that handles common patterns, not a
// full Nginx config parser.
func ParseNginx(reader io.Reader) ([]NginxConfig, error) {
	scanner := bufio.NewScanner(reader)
	var configs []NginxConfig
	var current *NginxConfig
	var currentLoc *NginxLocation

	inServer := false
	inLocation := false
	braceDepth := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")

		// Detect server block start
		if !inServer && strings.HasPrefix(line, "server") && strings.Contains(line, "{") {
			inServer = true
			braceDepth = 1
			cfg := NginxConfig{}
			current = &cfg
			// A one-line block ("server { listen 80; return 301 …; }") closes
			// itself on this line. Parse the directives before the closing
			// brace and complete the block here, or the block never closed:
			// every following line merged into it, later servers were
			// absorbed, and the incomplete config was dropped at EOF (the
			// same-line shape F8602 fixed for location blocks).
			if closeBraces > 0 {
				if start, end := strings.Index(line, "{"), strings.LastIndex(line, "}"); end > start {
					for _, part := range strings.Split(line[start+1:end], ";") {
						parseNginxServerDirective(current, part)
					}
				}
				configs = append(configs, *current)
				inServer = false
				current = nil
			}
			continue
		}

		if !inServer {
			// Outside any server block — skip
			continue
		}

		// Update brace depth
		braceDepth += openBraces - closeBraces

		// End of server block
		if braceDepth <= 0 {
			// A location still open here means the line closed BOTH blocks
			// at once ("…; } }").
			serverLevel := !inLocation
			inServer = false
			inLocation = false
			if current != nil {
				if serverLevel {
					// The server's last directive may share the closing-brace
					// line ("try_files $uri /index.html; }") — parse what
					// precedes the brace before closing, or it was silently
					// dropped (the same-line shapes F8602 and the location-end
					// fix covered for location blocks).
					if end := strings.Index(line, "}"); end > 0 {
						for _, part := range strings.Split(line[:end], ";") {
							parseNginxServerDirective(current, part)
						}
					}
				} else if currentLoc != nil {
					// The pending location's directives precede its own
					// closing brace on this line — parse and flush it, or
					// the whole location was silently lost.
					if end := strings.Index(line, "}"); end > 0 {
						for _, part := range strings.Split(line[:end], ";") {
							parseNginxLocationDirective(currentLoc, part)
						}
					}
					current.Locations = append(current.Locations, *currentLoc)
					current.Warnings = append(current.Warnings, locationWarnings(*currentLoc)...)
					currentLoc = nil
				}
				configs = append(configs, *current)
				current = nil
			}
			continue
		}

		// Detect location block
		if !inLocation && strings.HasPrefix(line, "location") && strings.Contains(line, "{") {
			mod, path := extractLocationModifierAndPath(line)
			loc := NginxLocation{Path: path, Modifier: mod}
			if closeBraces > 0 {
				// A one-line block ("location = /f { access_log off; }") is
				// complete here; staying "inside" it swallowed every
				// following server directive and location (F8602).
				if end := strings.LastIndex(line, "}"); end > strings.Index(line, "{") {
					for _, part := range strings.Split(line[strings.Index(line, "{")+1:end], ";") {
						parseNginxLocationDirective(&loc, part)
					}
				}
				if current != nil {
					current.Locations = append(current.Locations, loc)
					current.Warnings = append(current.Warnings, locationWarnings(loc)...)
				}
				continue
			}
			inLocation = true
			currentLoc = &loc
			continue
		}

		// Inside location block
		if inLocation {
			if closeBraces > 0 && openBraces == 0 {
				// The block's last directive may share the closing-brace line
				// ("proxy_pass http://backend; }", "deny all; }") — parse what
				// precedes the brace before closing, or that directive was
				// silently dropped (the same-line shape F8602 fixed for the
				// block's start).
				if end := strings.Index(line, "}"); end > 0 && currentLoc != nil {
					for _, part := range strings.Split(line[:end], ";") {
						parseNginxLocationDirective(currentLoc, part)
					}
				}
				// End of location block
				inLocation = false
				if current != nil && currentLoc != nil {
					current.Locations = append(current.Locations, *currentLoc)
					current.Warnings = append(current.Warnings, locationWarnings(*currentLoc)...)
				}
				currentLoc = nil
				continue
			}

			if currentLoc != nil {
				parseNginxLocationDirective(currentLoc, line)
			}
			continue
		}

		// Server-level directives
		parseNginxServerDirective(current, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading nginx config: %w", err)
	}

	return configs, nil
}

// ConvertToUWAS converts parsed NginxConfig blocks to UWAS Domain configs.
func ConvertToUWAS(configs []NginxConfig) []config.Domain {
	domains := make([]config.Domain, 0, len(configs))

	for _, nc := range configs {
		d := config.Domain{}

		// Host and aliases
		if len(nc.ServerNames) > 0 {
			first := nc.ServerNames[0]
			if first == "_" {
				d.Host = "example.com"
			} else {
				d.Host = first
			}
			if len(nc.ServerNames) > 1 {
				d.Aliases = nc.ServerNames[1:]
			}
		} else {
			d.Host = "example.com"
		}

		// Root
		d.Root = nc.Root

		// Index files
		if len(nc.IndexFiles) > 0 {
			d.IndexFiles = nc.IndexFiles
		}

		// SSL
		hasSSLListen := false
		for _, lp := range nc.ListenPorts {
			if strings.Contains(lp, "ssl") || strings.Contains(lp, "443") {
				hasSSLListen = true
				break
			}
		}

		if nc.SSLCert != "" {
			d.SSL = config.SSLConfig{
				Mode: "manual",
				Cert: nc.SSLCert,
				Key:  nc.SSLKey,
			}
		} else if hasSSLListen {
			d.SSL = config.SSLConfig{
				Mode: "auto",
			}
		}

		// Determine type based on directives
		domainType := determineDomainType(nc)
		d.Type = domainType

		switch domainType {
		case "php":
			d.PHP = buildPHPConfig(nc)
		case "proxy":
			d.Proxy = buildProxyConfig(nc)
		case "redirect":
			d.Redirect = buildRedirectConfig(nc)
		}

		// try_files / SPA mode
		tryFiles := collectTryFiles(nc)
		if len(tryFiles) > 0 {
			// Detect SPA mode: try_files ending with /index.html. A /index.php
			// front controller is not SPA mode: spa_mode makes the static
			// handler fall back to /index.html and ignore try_files (F3800).
			last := tryFiles[len(tryFiles)-1]
			baseLast := strings.SplitN(last, "?", 2)[0]
			if baseLast == "/index.html" {
				d.SPAMode = true
			}
			d.TryFiles = tryFiles
		}

		// "location /private/ { deny all; }": nothing under the path may be
		// served. blocked_paths is a substring match, so a prefix, exact or ^~
		// path carries over; a regex location has no equivalent and is not
		// translated.
		for _, loc := range nc.Locations {
			if loc.DenyAll && loc.Modifier != "~" && loc.Modifier != "~*" && loc.Path != "" && loc.Path != "/" {
				d.Security.BlockedPaths = append(d.Security.BlockedPaths, loc.Path)
			}
		}

		domains = append(domains, d)
	}

	return dropShadowedHTTPSRedirects(domains)
}

// dropShadowedHTTPSRedirects removes the plain-HTTP "return 301 https://..."
// server of a site whose HTTPS server is also migrated: two domains with one
// host fail config validation, and a domain with TLS already redirects HTTP
// to HTTPS (F8604).
func dropShadowedHTTPSRedirects(domains []config.Domain) []config.Domain {
	served := map[string]bool{}
	for _, d := range domains {
		if d.Type != "redirect" {
			served[strings.ToLower(d.Host)] = true
		}
	}
	out := domains[:0:0]
	for _, d := range domains {
		if d.Type == "redirect" && served[strings.ToLower(d.Host)] &&
			strings.HasPrefix(strings.ToLower(d.Redirect.Target), "https://") {
			continue
		}
		out = append(out, d)
	}
	return out
}

// NginxToYAML is a convenience function that parses Nginx config, converts to
// UWAS domains, and marshals to minimal, clean YAML (no zero-value fields).
func NginxToYAML(reader io.Reader) (string, error) {
	yaml, warnings, err := NginxToYAMLWithWarnings(reader)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, w := range warnings {
		b.WriteString("# WARNING: not migrated, the site is NOT protected by it: " + w + "\n")
	}
	return b.String() + yaml, nil
}

// NginxToYAMLWithWarnings is NginxToYAML plus the access-control directives
// that could not be translated and were dropped (F8900). Such a site is more
// open after migration than before, so callers must show the list.
func NginxToYAMLWithWarnings(reader io.Reader) (string, []string, error) {
	configs, err := ParseNginx(reader)
	if err != nil {
		return "", nil, err
	}
	if len(configs) == 0 {
		return "", nil, fmt.Errorf("no server blocks found")
	}

	var warnings []string
	for _, nc := range configs {
		name := "_"
		if len(nc.ServerNames) > 0 {
			name = nc.ServerNames[0]
		}
		for _, w := range nc.Warnings {
			warnings = append(warnings, name+": "+w)
		}
	}
	domains := ConvertToUWAS(configs)
	return domainsToYAML(domains), warnings, nil
}

// domainsToYAML generates clean, minimal YAML output for converted domains.
func domainsToYAML(domains []config.Domain) string {
	var b strings.Builder
	b.WriteString("# Converted from Nginx config by UWAS\n")
	b.WriteString("domains:\n")

	for _, d := range domains {
		fmt.Fprintf(&b, "  - host: %s\n", yamlScalar(d.Host))
		fmt.Fprintf(&b, "    type: %s\n", yamlScalar(d.Type))
		if d.Root != "" {
			fmt.Fprintf(&b, "    root: %s\n", yamlScalar(d.Root))
		}
		if len(d.Aliases) > 0 {
			b.WriteString("    aliases:\n")
			for _, a := range d.Aliases {
				fmt.Fprintf(&b, "      - %s\n", yamlScalar(a))
			}
		}
		if len(d.IndexFiles) > 0 {
			b.WriteString("    index_files:\n")
			for _, f := range d.IndexFiles {
				fmt.Fprintf(&b, "      - %s\n", yamlScalar(f))
			}
		}
		if d.SSL.Mode != "" {
			b.WriteString("    ssl:\n")
			fmt.Fprintf(&b, "      mode: %s\n", yamlScalar(d.SSL.Mode))
			if d.SSL.Cert != "" {
				fmt.Fprintf(&b, "      cert: %s\n", yamlScalar(d.SSL.Cert))
			}
			if d.SSL.Key != "" {
				fmt.Fprintf(&b, "      key: %s\n", yamlScalar(d.SSL.Key))
			}
		}
		if d.Type == "php" && d.PHP.FPMAddress != "" {
			b.WriteString("    php:\n")
			fmt.Fprintf(&b, "      fpm_address: %s\n", yamlScalar(d.PHP.FPMAddress))
			if len(d.PHP.IndexFiles) > 0 {
				b.WriteString("      index_files:\n")
				for _, f := range d.PHP.IndexFiles {
					fmt.Fprintf(&b, "        - %s\n", yamlScalar(f))
				}
			}
		}
		if d.Type == "proxy" && len(d.Proxy.Upstreams) > 0 {
			b.WriteString("    proxy:\n")
			b.WriteString("      upstreams:\n")
			for _, u := range d.Proxy.Upstreams {
				fmt.Fprintf(&b, "        - address: %s\n", yamlScalar(u.Address))
			}
		}
		if d.Type == "redirect" && d.Redirect.Target != "" {
			b.WriteString("    redirect:\n")
			fmt.Fprintf(&b, "      target: %s\n", yamlScalar(d.Redirect.Target))
			if d.Redirect.Status > 0 {
				fmt.Fprintf(&b, "      status: %d\n", d.Redirect.Status)
			}
			if d.Redirect.PreservePath {
				b.WriteString("      preserve_path: true\n")
			}
		}
		if d.SPAMode {
			b.WriteString("    spa_mode: true\n")
		}
		if len(d.TryFiles) > 0 {
			b.WriteString("    try_files:\n")
			for _, f := range d.TryFiles {
				fmt.Fprintf(&b, "      - %s\n", yamlScalar(f))
			}
		}
		if len(d.Security.BlockedPaths) > 0 {
			b.WriteString("    security:\n      blocked_paths:\n")
			for _, p := range d.Security.BlockedPaths {
				fmt.Fprintf(&b, "        - %s\n", yamlScalar(p))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

// yamlScalar returns s as a YAML scalar that parses back to exactly s. A
// value is written plain only when it round-trips as the same string; anything
// YAML would read differently (a leading "*" alias marker as in a wildcard
// server_name, a " #" comment, ": ", quotes, true/123/null) is written
// double-quoted, whose escapes are a superset of Go's strconv quoting.
func yamlScalar(s string) string {
	if s != "" && !strings.ContainsAny(s, "\"'\\\t\r\n") {
		var m map[string]any
		if yaml.Unmarshal([]byte("v: "+s), &m) == nil {
			if v, ok := m["v"].(string); ok && v == s {
				return s
			}
		}
	}
	return strconv.Quote(s)
}

// YAMLScalar is yamlScalar for converters outside this package (F8310).
func YAMLScalar(s string) string { return yamlScalar(s) }

// --- internal helpers ---

// parseNginxServerDirective records the server-level directives that the
// converter understands, plus the access-control directives it must warn
// about. Used by the main loop and by one-line server blocks.
func parseNginxServerDirective(cfg *NginxConfig, line string) {
	if w := untranslatedAccessDirective(line); w != "" {
		cfg.Warnings = append(cfg.Warnings, "server "+w)
	}
	if val := extractDirective(line, "server_name"); val != "" {
		cfg.ServerNames = strings.Fields(val)
	}
	if val := extractDirective(line, "root"); val != "" {
		cfg.Root = val
	}
	if val := extractDirective(line, "listen"); val != "" {
		cfg.ListenPorts = append(cfg.ListenPorts, val)
	}
	if val := extractDirective(line, "index"); val != "" {
		cfg.IndexFiles = strings.Fields(val)
	}
	// ssl_certificate_key must be checked before ssl_certificate to avoid
	// false match (ssl_certificate is a prefix of ssl_certificate_key).
	if val := extractDirective(line, "ssl_certificate_key"); val != "" {
		cfg.SSLKey = val
	} else if val := extractDirective(line, "ssl_certificate"); val != "" {
		cfg.SSLCert = val
	}
	if val := extractDirective(line, "proxy_pass"); val != "" {
		cfg.ProxyPass = val
	}
	if val := extractDirective(line, "return"); val != "" {
		cfg.Return = val
	}
	if val := extractDirective(line, "try_files"); val != "" {
		cfg.TryFiles = strings.Fields(val)
	}
}

// parseNginxLocationDirective records the directives of a location block that
// the converter understands.
func parseNginxLocationDirective(loc *NginxLocation, line string) {
	if w := untranslatedAccessDirective(line); w != "" {
		loc.Warnings = append(loc.Warnings, w)
	}
	if val := extractDirective(line, "proxy_pass"); val != "" {
		loc.ProxyPass = val
	}
	if val := extractDirective(line, "fastcgi_pass"); val != "" {
		loc.FastCGI = val
	}
	if val := extractDirective(line, "try_files"); val != "" {
		loc.TryFiles = strings.Fields(val)
	}
	if val := extractDirective(line, "return"); val != "" {
		loc.Return = val
	}
	if val := extractDirective(line, "deny"); val == "all" {
		loc.DenyAll = true
	}
}

// untranslatedAccessDirective names an access-control directive that has no
// UWAS equivalent in the migrated config (auth_basic, allow/deny lists,
// auth_request, satisfy, internal). It returns "" for anything else. "deny all"
// is judged separately: a prefix location carries over as blocked_paths.
func untranslatedAccessDirective(line string) string {
	line = strings.TrimSpace(line)
	for _, d := range []string{"auth_basic_user_file", "auth_basic", "auth_request", "satisfy", "allow"} {
		if val := extractDirective(line, d); val != "" {
			if d == "auth_basic" && val == "off" {
				return ""
			}
			return d + " " + val
		}
	}
	if val := extractDirective(line, "deny"); val != "" && val != "all" {
		return "deny " + val
	}
	if strings.TrimSuffix(line, ";") == "internal" {
		return "internal"
	}
	return ""
}

// locationWarnings reports what a location block asks for that is not carried
// over: its untranslated access directives and a "deny all" the converter
// cannot turn into blocked_paths (a regex location, or the site root).
func locationWarnings(loc NginxLocation) []string {
	var out []string
	for _, w := range loc.Warnings {
		out = append(out, fmt.Sprintf("location %s: %s", loc.Path, w))
	}
	if loc.DenyAll && (loc.Modifier == "~" || loc.Modifier == "~*" || loc.Path == "" || loc.Path == "/") {
		out = append(out, fmt.Sprintf("location %s %s: deny all", loc.Modifier, loc.Path))
	}
	return out
}

// extractDirective extracts the value of a simple Nginx directive.
// E.g., extractDirective("server_name example.com;", "server_name") => "example.com"
func extractDirective(line, directive string) string {
	line = strings.TrimSpace(line)
	val, ok := strings.CutPrefix(line, directive)
	if !ok || len(val) == 0 || (val[0] != ' ' && val[0] != '\t') {
		return ""
	}
	val = strings.TrimSuffix(val, ";")
	return strings.TrimSpace(val)
}

var locationRegexp = regexp.MustCompile(`^location\s+(?:(~\*?|=|\^~)\s+)?(\S+)\s*\{`)

func extractLocationModifierAndPath(line string) (modifier, path string) {
	m := locationRegexp.FindStringSubmatch(line)
	if len(m) >= 3 {
		return m[1], m[2]
	}
	return "", "/"
}

// determineDomainType inspects the parsed Nginx config and returns the UWAS
// domain type: "php", "proxy", "redirect", or "static".
func determineDomainType(nc NginxConfig) string {
	// Check for redirect (return 301/302)
	if nc.Return != "" {
		code, _ := parseReturnDirective(nc.Return)
		if code == 301 || code == 302 {
			return "redirect"
		}
	}

	// Check for proxy_pass at server level
	if nc.ProxyPass != "" {
		return "proxy"
	}

	// Check locations for PHP / proxy / redirect indicators
	hasPHP := false
	hasProxy := false
	hasRedirectLoc := false

	for _, loc := range nc.Locations {
		if loc.FastCGI != "" {
			hasPHP = true
		}
		if loc.Modifier == "~" && strings.Contains(loc.Path, `\.php`) {
			hasPHP = true
		}
		if loc.ProxyPass != "" {
			hasProxy = true
		}
		if loc.Return != "" {
			code, _ := parseReturnDirective(loc.Return)
			if code == 301 || code == 302 {
				hasRedirectLoc = true
			}
		}
	}

	// Also check index files for PHP hint
	for _, idx := range nc.IndexFiles {
		if strings.HasSuffix(idx, ".php") {
			hasPHP = true
			break
		}
	}

	if hasPHP {
		return "php"
	}
	if hasProxy {
		return "proxy"
	}
	if hasRedirectLoc && !hasPHP && !hasProxy {
		// Only mark as redirect if there is nothing else going on
		return "redirect"
	}
	return "static"
}

// parseReturnDirective parses "301 https://..." into status code and target.
func parseReturnDirective(val string) (int, string) {
	parts := strings.Fields(val)
	if len(parts) < 2 {
		return 0, ""
	}
	var code int
	if _, err := fmt.Sscanf(parts[0], "%d", &code); err != nil {
		return 0, ""
	}
	return code, parts[1]
}

func buildPHPConfig(nc NginxConfig) config.PHPConfig {
	php := config.PHPConfig{}

	// Find FPM address from fastcgi_pass in locations
	for _, loc := range nc.Locations {
		if loc.FastCGI != "" {
			php.FPMAddress = loc.FastCGI
			break
		}
	}

	// Gather PHP index files
	var phpIdx []string
	for _, idx := range nc.IndexFiles {
		if strings.HasSuffix(idx, ".php") {
			phpIdx = append(phpIdx, idx)
		}
	}
	if len(phpIdx) > 0 {
		php.IndexFiles = phpIdx
	}

	return php
}

func buildProxyConfig(nc NginxConfig) config.ProxyConfig {
	proxy := config.ProxyConfig{}

	// Collect all proxy_pass targets
	seen := make(map[string]bool)
	addUpstream := func(addr string) {
		if addr != "" && !seen[addr] {
			seen[addr] = true
			proxy.Upstreams = append(proxy.Upstreams, config.Upstream{
				Address: addr,
				Weight:  1,
			})
		}
	}

	if nc.ProxyPass != "" {
		addUpstream(nc.ProxyPass)
	}
	for _, loc := range nc.Locations {
		if loc.ProxyPass != "" {
			addUpstream(loc.ProxyPass)
		}
	}

	return proxy
}

func buildRedirectConfig(nc NginxConfig) config.RedirectConfig {
	redirect := config.RedirectConfig{}

	// Check server-level return first
	if nc.Return != "" {
		code, target := parseReturnDirective(nc.Return)
		if code == 301 || code == 302 {
			redirect.Status = code
			redirect.Target = target
			// If the target contains $request_uri or $uri, preserve path
			if strings.Contains(target, "$request_uri") || strings.Contains(target, "$uri") {
				redirect.PreservePath = true
				// Clean the target of nginx variables for UWAS
				redirect.Target = strings.ReplaceAll(redirect.Target, "$request_uri", "")
				redirect.Target = strings.ReplaceAll(redirect.Target, "$uri", "")
			}
			return redirect
		}
	}

	// Check location-level returns
	for _, loc := range nc.Locations {
		if loc.Return != "" {
			code, target := parseReturnDirective(loc.Return)
			if code == 301 || code == 302 {
				redirect.Status = code
				redirect.Target = target
				if strings.Contains(target, "$request_uri") || strings.Contains(target, "$uri") {
					redirect.PreservePath = true
					redirect.Target = strings.ReplaceAll(redirect.Target, "$request_uri", "")
					redirect.Target = strings.ReplaceAll(redirect.Target, "$uri", "")
				}
				return redirect
			}
		}
	}

	return redirect
}

// collectTryFiles gathers try_files from server level and location blocks.
func collectTryFiles(nc NginxConfig) []string {
	// Prefer server-level try_files
	if len(nc.TryFiles) > 0 {
		return nc.TryFiles
	}
	// Fall back to the root location's try_files
	for _, loc := range nc.Locations {
		if loc.Path == "/" && len(loc.TryFiles) > 0 {
			return loc.TryFiles
		}
	}
	return nil
}
