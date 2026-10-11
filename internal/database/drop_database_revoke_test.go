package database

import (
	"fmt"
	"strings"
	"testing"
)

// F11600: DROP DATABASE leaves privileges behind, so DropDatabase must revoke
// the schema-level grants of accounts other than the one it drops.
func TestDropDatabaseRevokesOtherGrantees(t *testing.T) {
	saveHooks(t)
	var batches []string
	runMySQLFn = func(sql string) (string, error) {
		if strings.Contains(sql, "FROM mysql.db WHERE") {
			if !strings.Contains(sql, `'site\\_a'`) || !strings.Contains(sql, `'site_a'`) {
				t.Errorf("lookup must match the escaped and plain grant forms: %s", sql)
			}
			return "User\tHost\t\n" +
				"site_user\t%\tesc\n" +
				"legacy_user\tlocalhost\tplain\n" +
				"root\tlocalhost\tesc\n" +
				"site_user\t%\tesc\n", nil
		}
		batches = append(batches, sql)
		return "", nil
	}

	if err := DropDatabase("site_a", "site_a", "localhost"); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 {
		t.Fatalf("want one drop batch, got %d", len(batches))
	}
	b := batches[0]
	for _, want := range []string{
		"REVOKE ALL PRIVILEGES ON `site\\_a`.* FROM 'site_user'@'%';",
		"REVOKE ALL PRIVILEGES ON `site_a`.* FROM 'legacy_user'@'localhost';",
		"DROP DATABASE IF EXISTS `site_a`;",
		"DROP USER IF EXISTS 'site_a'@'localhost';",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("batch lacks %q:\n%s", want, b)
		}
	}
	if strings.Count(b, "'site_user'@'%'") != 1 {
		t.Errorf("duplicate grantee must be revoked once:\n%s", b)
	}
	if strings.Contains(b, "'root'@") && strings.Contains(b, "REVOKE ALL PRIVILEGES ON `site\\_a`.* FROM 'root'") {
		t.Errorf("protected account must be left alone:\n%s", b)
	}
	if strings.Index(b, "REVOKE") > strings.Index(b, "DROP DATABASE") {
		t.Errorf("REVOKE must run before DROP DATABASE:\n%s", b)
	}
}

func TestDropDatabaseStillDropsWhenGranteeLookupFails(t *testing.T) {
	saveHooks(t)
	var batches []string
	runMySQLFn = func(sql string) (string, error) {
		if strings.Contains(sql, "FROM mysql.db WHERE") {
			return "", fmt.Errorf("lookup failed")
		}
		batches = append(batches, sql)
		return "", nil
	}
	if err := DropDatabase("plain", "plain", "localhost"); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || strings.Contains(batches[0], "REVOKE") || !strings.Contains(batches[0], "DROP DATABASE IF EXISTS `plain`;") {
		t.Fatalf("unexpected batch: %v", batches)
	}
}
