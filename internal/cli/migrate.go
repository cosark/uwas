package cli

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	nginxmigrate "github.com/uwaserver/uwas/internal/migrate"
)

// MigrateCommand converts Nginx/Apache configs to UWAS YAML.
type MigrateCommand struct{}

func (m *MigrateCommand) Name() string        { return "migrate" }
func (m *MigrateCommand) Description() string { return "Convert Nginx/Apache config to UWAS YAML" }

func (m *MigrateCommand) Help() string {
	return `Subcommands:
  nginx <file>    Convert an Nginx config file to UWAS YAML
  apache <file>   Convert an Apache config file to UWAS YAML

Examples:
  uwas migrate nginx /etc/nginx/sites-enabled/example.conf
  uwas migrate apache /etc/apache2/sites-enabled/example.conf`
}

func (m *MigrateCommand) Run(args []string) error {
	if len(args) < 2 {
		fmt.Println(m.Help())
		return nil
	}

	format := args[0]
	file := args[1]

	switch format {
	case "nginx":
		return migrateNginx(file)
	case "apache":
		return migrateApache(file)
	default:
		return fmt.Errorf("unknown format %q (use: nginx, apache)", format)
	}
}

// --- Nginx migration ---

func migrateNginx(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()

	yaml, err := nginxmigrate.NginxToYAML(f)
	if err != nil {
		return fmt.Errorf("migrate %s: %w", file, err)
	}

	fmt.Print(yaml)
	// The YAML begins with "# WARNING" lines for access rules that were not
	// migrated; repeat the count on stderr, where redirecting stdout to a
	// file does not hide it (F8900).
	if n := strings.Count(yaml, "# WARNING:"); n > 0 {
		fmt.Fprintf(os.Stderr, "uwas: %d access-control directive(s) were NOT migrated; see the # WARNING lines at the top of the output\n", n)
	}
	return nil
}

// --- Apache migration ---

type apacheVHost struct {
	serverName   string
	documentRoot string
	sslEngine    bool
	sslCertFile  string
	sslKeyFile   string
	proxyPass    []apacheProxy
	locations    []apacheProxy // path-scoped ProxyPass entries
	aliases      []string
	listen       string
	warnings     []string // access rules that are not migrated (F8901)
}

type apacheProxy struct {
	path   string
	target string
}

func migrateApache(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()

	vhosts := parseApacheConfig(f)
	if len(vhosts) == 0 {
		return fmt.Errorf("no VirtualHost blocks found in %s", file)
	}

	yaml := convertApacheToYAML(vhosts)
	fmt.Print(yaml)
	if n := strings.Count(yaml, "# WARNING:"); n > 0 {
		fmt.Fprintf(os.Stderr, "uwas: %d access/redirect directive(s) were NOT migrated; see the # WARNING lines at the top of the output\n", n)
	}
	return nil
}

func parseApacheConfig(f *os.File) []apacheVHost {
	var vhosts []apacheVHost
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 64KB initial, 1MB max
	inVHost := false
	var current apacheVHost

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "<VirtualHost") {
			inVHost = true
			current = apacheVHost{}
			// Extract listen address from <VirtualHost *:443>
			if addr := extractApacheVHostAddr(line); addr != "" {
				current.listen = addr
			}
			continue
		}

		if strings.HasPrefix(line, "</VirtualHost") {
			inVHost = false
			vhosts = append(vhosts, current)
			continue
		}

		if !inVHost {
			continue
		}

		// Parse directives inside VirtualHost
		lower := strings.ToLower(line)

		if apacheAccessDirective(lower) {
			current.warnings = append(current.warnings, line)
		}

		if strings.HasPrefix(lower, "servername") {
			current.serverName = stripApachePort(extractApacheValue(line))
		}
		if strings.HasPrefix(lower, "serveralias") {
			for _, a := range strings.Fields(line)[1:] {
				if a = stripApachePort(a); a != "" {
					current.aliases = append(current.aliases, a)
				}
			}
		}
		if strings.HasPrefix(lower, "documentroot") {
			current.documentRoot = extractApacheValue(line)
		}
		if strings.HasPrefix(lower, "sslengine") {
			val := strings.ToLower(extractApacheValue(line))
			current.sslEngine = (val == "on")
		}
		if strings.HasPrefix(lower, "sslcertificatefile") {
			current.sslCertFile = extractApacheValue(line)
		}
		if strings.HasPrefix(lower, "sslcertificatekeyfile") {
			current.sslKeyFile = extractApacheValue(line)
		}
		if strings.HasPrefix(lower, "proxypass ") && !strings.HasPrefix(lower, "proxypassreverse") {
			parts := strings.Fields(line)
			// "ProxyPass /static !" excludes a path from proxying; it has no
			// upstream to migrate (F8601).
			if len(parts) >= 3 && parts[2] != "!" {
				p := apacheProxy{path: parts[1], target: parts[2]}
				if p.path == "/" {
					current.proxyPass = append(current.proxyPass, p)
				} else {
					current.locations = append(current.locations, p)
				}
			}
		}
	}

	return vhosts
}

// stripApachePort drops the ":port" of "ServerName host:port" (and of an
// alias): a UWAS host never carries a port (F8600).
func stripApachePort(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], "]") && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return h
}

// mergeApacheVHosts folds the vhosts of one ServerName (the usual *:80 and
// *:443 pair) into a single domain; two domains with one host fail config
// validation (F8600). The first non-empty value of each setting wins, except
// that a certificate pair or an https listener is never lost to a plain one.
func mergeApacheVHosts(vhosts []apacheVHost) []apacheVHost {
	var out []apacheVHost
	idx := map[string]int{}
	for _, vh := range vhosts {
		key := strings.ToLower(vh.serverName)
		i, ok := idx[key]
		if key == "" || !ok {
			if key != "" {
				idx[key] = len(out)
			}
			out = append(out, vh)
			continue
		}
		m := &out[i]
		if m.documentRoot == "" {
			m.documentRoot = vh.documentRoot
		}
		m.sslEngine = m.sslEngine || vh.sslEngine
		if m.sslCertFile == "" {
			m.sslCertFile, m.sslKeyFile = vh.sslCertFile, vh.sslKeyFile
		}
		if strings.Contains(vh.listen, "443") && !strings.Contains(m.listen, "443") {
			m.listen = vh.listen
		}
		m.proxyPass = append(m.proxyPass, vh.proxyPass...)
		m.locations = append(m.locations, vh.locations...)
		m.aliases = append(m.aliases, vh.aliases...)
		m.warnings = append(m.warnings, vh.warnings...)
	}
	return out
}

// apacheAccessDirective reports a directive that restricts or redirects access
// and has no translation in the migrated config: the site is more open after
// migration than before, so it is reported instead of dropped (F8901). lower is
// the lower-cased, trimmed line.
func apacheAccessDirective(lower string) bool {
	for _, p := range []string{
		"<directory", "<location", "<files", "<limit",
		"require ", "<requireall", "<requireany", "<requirenone",
		"order ", "allow from", "deny from",
		"authtype", "authname", "authuserfile", "authgroupfile",
		"redirect ", "redirectmatch", "redirectpermanent", "rewriterule", "rewritecond",
	} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

var apacheVHostAddrRegexp = regexp.MustCompile(`<VirtualHost\s+([^>]+)>`)

func extractApacheVHostAddr(line string) string {
	m := apacheVHostAddrRegexp.FindStringSubmatch(line)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractApacheValue(line string) string {
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return ""
	}
	arg := strings.TrimSpace(line[len(parts[0]):])
	quote := arg[0]
	if quote != '"' && quote != '\'' {
		return parts[1]
	}
	var value strings.Builder
	for i := 1; i < len(arg); i++ {
		if arg[i] == quote {
			break
		}
		if arg[i] == '\\' && i+1 < len(arg) && (arg[i+1] == quote || arg[i+1] == '\\') {
			i++
		}
		value.WriteByte(arg[i])
	}
	return value.String()
}

func convertApacheToYAML(vhosts []apacheVHost) string {
	var b strings.Builder
	merged := mergeApacheVHosts(vhosts)
	for _, vh := range merged {
		host := vh.serverName
		if host == "" {
			host = "example.com"
		}
		for _, w := range vh.warnings {
			b.WriteString("# WARNING: not migrated, the site is NOT protected by it: " + host + ": " + w + "\n")
		}
	}
	b.WriteString("# Converted from Apache config by UWAS\n")
	b.WriteString("domains:\n")

	for _, vh := range merged {
		host := vh.serverName
		if host == "" {
			host = "example.com"
		}

		b.WriteString(fmt.Sprintf("  - host: %s\n", nginxmigrate.YAMLScalar(host)))
		if aliases := uniqueApacheAliases(host, vh.aliases); len(aliases) > 0 {
			b.WriteString("    aliases:\n")
			for _, a := range aliases {
				b.WriteString(fmt.Sprintf("      - %s\n", nginxmigrate.YAMLScalar(a)))
			}
		}

		// Determine type
		hasProxy := len(vh.proxyPass) > 0
		if hasProxy {
			b.WriteString("    type: proxy\n")
		} else {
			b.WriteString("    type: static\n")
		}

		if vh.documentRoot != "" {
			b.WriteString(fmt.Sprintf("    root: %s\n", nginxmigrate.YAMLScalar(vh.documentRoot)))
		}

		// SSL
		if vh.sslEngine || vh.sslCertFile != "" {
			b.WriteString("    ssl:\n")
			if vh.sslCertFile != "" {
				b.WriteString("      mode: manual\n")
				b.WriteString(fmt.Sprintf("      cert: %s\n", nginxmigrate.YAMLScalar(vh.sslCertFile)))
				if vh.sslKeyFile != "" {
					b.WriteString(fmt.Sprintf("      key: %s\n", nginxmigrate.YAMLScalar(vh.sslKeyFile)))
				}
			} else {
				b.WriteString("      mode: auto\n")
			}
		} else if strings.Contains(vh.listen, "443") {
			b.WriteString("    ssl:\n")
			b.WriteString("      mode: auto\n")
		}

		// Proxy config
		if hasProxy {
			b.WriteString("    proxy:\n")
			b.WriteString("      upstreams:\n")
			for _, p := range vh.proxyPass {
				b.WriteString(fmt.Sprintf("        - address: %s\n", nginxmigrate.YAMLScalar(p.target)))
			}
		}

		// Path-scoped ProxyPass: only that prefix goes to the backend, the
		// rest of the vhost keeps being served from its root (F8601).
		if len(vh.locations) > 0 {
			b.WriteString("    locations:\n")
			for _, l := range vh.locations {
				b.WriteString(fmt.Sprintf("      - match: %s\n", nginxmigrate.YAMLScalar(l.path)))
				b.WriteString(fmt.Sprintf("        proxy_pass: %s\n", nginxmigrate.YAMLScalar(strings.TrimRight(l.target, "/"))))
				b.WriteString("        strip_prefix: true\n")
			}
		}

		b.WriteString("\n")
	}

	return b.String()
}

// uniqueApacheAliases returns the aliases without repeats and without the
// primary host itself.
func uniqueApacheAliases(host string, aliases []string) []string {
	seen := map[string]bool{strings.ToLower(host): true}
	var out []string
	for _, a := range aliases {
		if k := strings.ToLower(a); !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}
