package admin

// R131 fork C: command/argument injection matrix. The admin tests normally
// replace every exec seam with a no-op; this one restores the real seams and
// puts recording shims for the system commands first on PATH, so hostile input
// is sent through the REAL handlers (admin token) and the exact argv / stdin /
// crontab content that would reach the OS is observed. Nothing privileged ever
// runs: every command resolves to a shim that only appends a record.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uwaserver/uwas/internal/database"
	"github.com/uwaserver/uwas/internal/firewall"
	"github.com/uwaserver/uwas/internal/services"
)

const injMark = "ZZINJ"

type shimCall struct {
	name  string
	args  []string
	stdin string
	file  string // crontab file content
}

const shimScript = `#!/bin/sh
n=$(basename "$0")
log="$SHIM_LOG"
{
  printf 'BEGIN %s\n' "$n"
  for a in "$@"; do printf 'ARG '; printf '%s' "$a" | od -An -v -tx1 | tr -d ' \n'; printf '\n'; done
  if [ ! -t 0 ]; then printf 'STDIN '; cat | od -An -v -tx1 | tr -d ' \n'; printf '\n'; fi
  case "$n" in
    crontab) if [ "$1" != "-l" ] && [ -f "$1" ]; then printf 'FILE '; od -An -v -tx1 < "$1" | tr -d ' \n'; printf '\n'; fi ;;
  esac
  printf 'END\n'
} >> "$log"
case "$n" in
  crontab) if [ "$1" = "-l" ]; then echo "no crontab for test" >&2; exit 1; fi ;;
  id) exit 1 ;;
esac
exit 0
`

func installRecordingShims(t *testing.T) (readCalls func() []shimCall) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	if err := os.WriteFile(log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{
		"systemctl", "apt", "apt-get", "dnf", "useradd", "userdel", "chpasswd", "crontab",
		"mysql", "mariadb", "mysqldump", "mariadb-dump", "mysqladmin", "docker", "git", "wp",
		"ufw", "chown", "chmod", "id", "service", "curl", "tar",
	} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte(shimScript), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SHIM_LOG", log)

	return func() []shimCall {
		raw, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		var calls []shimCall
		var cur *shimCall
		dec := func(h string) string {
			b, _ := hex.DecodeString(h)
			return string(b)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			switch {
			case strings.HasPrefix(line, "BEGIN "):
				cur = &shimCall{name: strings.TrimPrefix(line, "BEGIN ")}
			case strings.HasPrefix(line, "ARG ") && cur != nil:
				cur.args = append(cur.args, dec(strings.TrimPrefix(line, "ARG ")))
			case strings.HasPrefix(line, "STDIN ") && cur != nil:
				cur.stdin = dec(strings.TrimPrefix(line, "STDIN "))
			case strings.HasPrefix(line, "FILE ") && cur != nil:
				cur.file = dec(strings.TrimPrefix(line, "FILE "))
			case line == "END" && cur != nil:
				calls = append(calls, *cur)
				cur = nil
			}
		}
		return calls
	}
}

// restoreRealSeams points the admin hooks that TestMain neutralised back at the
// real implementations (which now resolve to the recording shims).
func restoreRealSeams(t *testing.T) {
	t.Helper()
	oc, od := databaseCreateDatabase, databaseDropDatabase
	ss, st, sr := servicesStartService, servicesStopService, servicesRestartService
	fa, fd := firewallAllowPort, firewallDenyPort
	t.Cleanup(func() {
		databaseCreateDatabase, databaseDropDatabase = oc, od
		servicesStartService, servicesStopService, servicesRestartService = ss, st, sr
		firewallAllowPort, firewallDenyPort = fa, fd
	})
	databaseCreateDatabase, databaseDropDatabase = database.CreateDatabase, database.DropDatabase
	servicesStartService, servicesStopService, servicesRestartService = services.StartService, services.StopService, services.RestartService
	firewallAllowPort, firewallDenyPort = firewall.AllowPortFrom, firewall.DenyPortFrom
}

// sqlOutsideLiterals returns the statements' text with every quoted literal
// ('..', "..", `..`) removed, honouring MySQL's backslash escapes and doubled
// quotes. Hostile text that stays inside a literal is inert; anything left in
// the result is executable SQL.
func sqlOutsideLiterals(sql string) string {
	var out strings.Builder
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c != '\'' && c != '"' && c != '`' {
			out.WriteByte(c)
			continue
		}
		q := c
		i++
		for ; i < len(sql); i++ {
			if sql[i] == '\\' && q != '`' {
				i++
				continue
			}
			if sql[i] == q {
				if i+1 < len(sql) && sql[i+1] == q { // doubled quote
					i++
					continue
				}
				break
			}
		}
		out.WriteString("<lit>")
	}
	return out.String()
}

func TestCommandInjectionArgvMatrix(t *testing.T) {
	th, srv, _ := newTenantHarness(t)
	calls := installRecordingShims(t)
	restoreRealSeams(t)

	hostile := []string{
		injMark + "'; DROP DATABASE mysql; -- ",
		injMark + "`touch /tmp/" + injMark + "`",
		injMark + "$(touch /tmp/" + injMark + ")",
		"-" + injMark,
		"--exec=" + injMark,
		injMark + "\n* * * * * root touch /tmp/" + injMark,
		injMark + "\\' OR 1=1 -- ",
		injMark + "\" OR \"1\"=\"1",
		injMark + "%h%u",
		" " + injMark,
	}

	type vec struct{ method, path, body string }
	var vecs []vec
	for _, h := range hostile {
		jq := q(h)
		vecs = append(vecs,
			vec{"POST", "/api/v1/cron", `{"schedule":"* * * * *","command":` + jq + `,"domain":"a.example"}`},
			vec{"POST", "/api/v1/cron", `{"schedule":` + jq + `,"command":"/bin/true","domain":"a.example"}`},
			vec{"POST", "/api/v1/cron", `{"schedule":"* * * * *","command":"/bin/true","domain":` + jq + `,"comment":` + jq + `}`},
			vec{"POST", "/api/v1/firewall/allow", `{"port":` + jq + `,"proto":"tcp","from":""}`},
			vec{"POST", "/api/v1/firewall/allow", `{"port":"8080","proto":` + jq + `,"from":""}`},
			vec{"POST", "/api/v1/firewall/allow", `{"port":"8080","proto":"tcp","from":` + jq + `}`},
			vec{"POST", "/api/v1/firewall/deny", `{"port":"8081","proto":"udp","from":` + jq + `}`},
			vec{"POST", "/api/v1/database/create", `{"name":` + jq + `,"user":"u1","password":"p"}`},
			vec{"POST", "/api/v1/database/create", `{"name":"d1","user":` + jq + `,"password":"p"}`},
			vec{"POST", "/api/v1/database/create", `{"name":"d1","user":"u1","password":` + jq + `,"host":` + jq + `}`},
			vec{"POST", "/api/v1/database/users/password", `{"user":"u1","host":` + jq + `,"password":` + jq + `}`},
			vec{"POST", "/api/v1/database/users/password", `{"user":` + jq + `,"password":"x"}`},
			vec{"POST", "/api/v1/database/remote-access", `{"user":"u1","host":` + jq + `,"password":` + jq + `,"database":` + jq + `}`},
			vec{"DELETE", "/api/v1/database/users", `{"user":"u1","host":` + jq + `}`},
			vec{"DELETE", "/api/v1/database/d1", `{"user":` + jq + `,"host":` + jq + `}`},
			vec{"POST", "/api/v1/database/" + urlSeg(h) + "/import", `SELECT 1;`},
			vec{"POST", "/api/v1/services/" + urlSeg(h) + "/start", `{}`},
			vec{"POST", "/api/v1/services/" + urlSeg(h) + "/restart", `{}`},
			vec{"POST", "/api/v1/packages/install", `{"id":` + jq + `}`},
			vec{"POST", "/api/v1/packages/install", `{"id":"redis","action":` + jq + `}`},
			vec{"POST", "/api/v1/users/a.example/ssh-keys", `{"public_key":` + q("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "+h) + `}`},
			vec{"POST", "/api/v1/users/a.example/ssh-keys", `{"public_key":` + q("ssh-ed25519 "+h) + `}`},
			vec{"POST", "/api/v1/wordpress/sites/a.example/plugin/activate/" + urlSeg(h), `{}`},
			vec{"POST", "/api/v1/wordpress/sites/a.example/plugin/" + urlSeg(h) + "/akismet", `{}`},
			vec{"POST", "/api/v1/wordpress/sites/a.example/change-password", `{"username":` + jq + `,"password":` + jq + `}`},
			vec{"POST", "/api/v1/users", `{"domain":` + jq + `}`},
			vec{"DELETE", "/api/v1/users/" + urlSeg(h), ``},
		)
	}

	// Tenant-reachable vectors (domain-scoped routes) are also sent as the
	// reseller and the plain user that own a.example.
	tenantPrefixes := []string{"/api/v1/users/a.example/ssh-keys", "/api/v1/wordpress/"}
	for _, v := range vecs {
		_, _ = th.req(v.method, v.path, "admin", v.body)
		for _, p := range tenantPrefixes {
			if strings.HasPrefix(v.path, p) {
				_, _ = th.req(v.method, v.path, "ra", v.body)
				_, _ = th.req(v.method, v.path, "ua", v.body)
			}
		}
	}

	all := calls()
	for _, d := range srv.config.Domains {
		if d.Host == "a.example" {
			assertAuthorizedKeysCanonical(t, filepath.Join(filepath.Dir(d.Root), ".ssh", "authorized_keys"))
		}
	}
	counts := map[string]int{}
	marked := map[string]int{}
	for _, c := range all {
		counts[c.name]++
		if strings.Contains(strings.Join(c.args, "\x00")+c.stdin+c.file, injMark) {
			marked[c.name]++
		}
	}
	t.Logf("shim calls: %v ; carrying hostile data: %v", counts, marked)

	for _, c := range all {
		for i, a := range c.args {
			if !strings.Contains(a, injMark) {
				continue
			}
			if strings.HasPrefix(a, "-") {
				t.Errorf("FLAG INJECTION: %s argv[%d] = %q (full: %q)", c.name, i, a, c.args)
			}
			if strings.ContainsAny(a, "\n\r") {
				t.Errorf("NEWLINE in argv: %s argv[%d] = %q", c.name, i, a)
			}
		}
		if c.stdin != "" && (c.name == "mysql" || c.name == "mariadb") {
			if rest := sqlOutsideLiterals(c.stdin); strings.Contains(rest, injMark) {
				t.Errorf("SQL INJECTION via %s stdin: hostile text outside a literal.\nSQL: %q\nOUTSIDE: %q", c.name, c.stdin, rest)
			}
		}
		if c.name == "crontab" && c.file != "" {
			for _, line := range strings.Split(c.file, "\n") {
				if strings.Contains(line, injMark) && !strings.HasPrefix(line, "#") && !looksLikeSingleCronLine(line) {
					t.Errorf("CRONTAB INJECTION: line %q", line)
				}
			}
			if n := strings.Count(c.file, "\n"); n > 2 {
				t.Errorf("CRONTAB wrote %d lines for one Add: %q", n, c.file)
			}
		}
		if c.name == "chpasswd" && strings.Count(c.stdin, "\n") > 1 {
			t.Errorf("chpasswd stdin has multiple lines: %q", c.stdin)
		}
		if c.name == "git" || c.name == "useradd" || c.name == "userdel" {
			for _, a := range c.args {
				if strings.Contains(a, injMark) {
					t.Errorf("%s reached with hostile arg: %q", c.name, c.args)
				}
			}
		}
	}
}

// Every line the SSH-key route ever wrote must be a bare "<type> <base64>" key:
// no options prefix (command=, from=, ...), no comment carrying hostile text.
func assertAuthorizedKeysCanonical(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("no authorized_keys written (%v)", err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[0], "ssh-") || strings.Contains(line, injMark) {
			t.Errorf("authorized_keys line is not a bare canonical key: %q", line)
		}
	}
}

func looksLikeSingleCronLine(line string) bool {
	f := strings.Fields(line)
	return len(f) >= 6 || (len(f) >= 2 && strings.HasPrefix(f[0], "@"))
}

// urlSeg escapes s for use as one URL path segment.
func urlSeg(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

// The detector itself needs a control: a statement whose quote is NOT escaped
// must leave the hostile text outside any literal, an escaped one must not.
func TestSQLLiteralScannerControl(t *testing.T) {
	bad := `CREATE USER 'a'@'h' IDENTIFIED BY 'x'; DROP DATABASE ZZINJ; -- '`
	if !strings.Contains(sqlOutsideLiterals(bad), "ZZINJ") {
		t.Fatalf("scanner missed an unescaped quote break-out: %q", sqlOutsideLiterals(bad))
	}
	good := `CREATE USER 'a'@'h' IDENTIFIED BY 'x\'; DROP DATABASE ZZINJ; -- ';`
	if strings.Contains(sqlOutsideLiterals(good), "ZZINJ") {
		t.Fatalf("scanner flagged an escaped quote: %q", sqlOutsideLiterals(good))
	}
	dbl := "CREATE DATABASE `a``; DROP ZZINJ; -- `;"
	if strings.Contains(sqlOutsideLiterals(dbl), "ZZINJ") {
		t.Fatalf("scanner flagged a doubled backtick: %q", sqlOutsideLiterals(dbl))
	}
}
