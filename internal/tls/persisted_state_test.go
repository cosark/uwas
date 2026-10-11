package uwastls

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
)

// F15400: a legacy Unicode directory and the A-label directory a later renewal
// wrote collapse onto one key; the choice between them must not depend on map
// iteration order, and the newer certificate must win.
func TestCollapsedCertDirectoriesLoadTheNewestEveryTime(t *testing.T) {
	older, oc, ok := generateTestCertWithExpiry(t, idnPuny, 5*24*time.Hour)
	newer, nc, nk := generateTestCertWithExpiry(t, idnPuny, 80*24*time.Hour)
	for i := 0; i < 60; i++ {
		m := testManager(t, []config.Domain{{Host: idnUnicode, SSL: config.SSLConfig{Mode: "auto"}}})
		// Save the newer one under the Unicode name and the older under the
		// A-label so the answer is not simply "prefer the A-label directory".
		if err := m.storage.Save(idnUnicode, newer, nk, nc); err != nil {
			t.Fatal(err)
		}
		if err := m.storage.Save(idnPuny, older, ok, oc); err != nil {
			t.Fatal(err)
		}
		m.LoadExistingCerts()
		v, found := m.certs.Load(idnPuny)
		if !found {
			t.Fatal("no certificate loaded")
		}
		if left := time.Until(v.(*tls.Certificate).Leaf.NotAfter); left < 30*24*time.Hour {
			t.Fatalf("run %d: loaded the certificate expiring in %v, want the newer one", i, left.Round(time.Hour))
		}
	}
}

// With equal expiry the directory already named after the key wins, so the
// choice is still deterministic.
func TestCollapsedCertDirectoriesTieGoesToTheALabel(t *testing.T) {
	c, cp, kp := generateTestCertWithExpiry(t, idnPuny, 80*24*time.Hour)
	for i := 0; i < 30; i++ {
		m := testManager(t, []config.Domain{{Host: idnUnicode, SSL: config.SSLConfig{Mode: "auto"}}})
		if err := m.storage.Save(idnUnicode, c, kp, cp); err != nil {
			t.Fatal(err)
		}
		if err := m.storage.Save(idnPuny, c, kp, cp); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		m.logger.Logger = slog.New(slog.NewTextHandler(&buf, nil))
		m.LoadExistingCerts()
		if !strings.Contains(buf.String(), "using="+idnPuny) {
			t.Fatalf("run %d: tie did not go to the A-label directory: %s", i, buf.String())
		}
	}
}

// F15401: a certificate that cannot be loaded is reported, naming the
// directory; a directory without a cert.pem is not a certificate and is not.
func TestUnreadableCertificateIsReportedNotDroppedSilently(t *testing.T) {
	m := testManager(t, nil)
	var buf bytes.Buffer
	m.logger.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	for _, h := range []string{"good.example", "bad.example", "nokey.example"} {
		c, cp, kp := generateTestCertWithExpiry(t, h, 80*24*time.Hour)
		if err := m.storage.Save(h, c, kp, cp); err != nil {
			t.Fatal(err)
		}
	}
	base := m.storage.baseDir
	data, _ := os.ReadFile(filepath.Join(base, "bad.example", "cert.pem"))
	if err := os.WriteFile(filepath.Join(base, "bad.example", "cert.pem"), data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(base, "nokey.example", "key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "empty.example"), 0o700); err != nil {
		t.Fatal(err)
	}

	m.LoadExistingCerts()

	if !m.HasCert("good.example") {
		t.Error("the intact certificate was not loaded")
	}
	out := buf.String()
	for _, want := range []string{"bad.example", "nokey.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("no log line names the skipped directory %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "empty.example") {
		t.Errorf("a directory with no cert.pem was reported as a lost certificate:\n%s", out)
	}
	if strings.Contains(out, "good.example") && strings.Contains(out, "skipping unreadable certificate on disk\" directory=good.example") {
		t.Errorf("the intact certificate was reported as skipped:\n%s", out)
	}
}

func TestLoadAllStillReturnsOnlyTheLoadableCertificates(t *testing.T) {
	s := NewCertStorage(t.TempDir())
	c, cp, kp := generateTestCertWithExpiry(t, "ok.example", 80*24*time.Hour)
	if err := s.Save("ok.example", c, kp, cp); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.baseDir, "junk.example"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadAll()
	if err != nil || len(got) != 1 || got["ok.example"] == nil {
		t.Fatalf("LoadAll = %v, %v; want only ok.example", got, err)
	}
}
