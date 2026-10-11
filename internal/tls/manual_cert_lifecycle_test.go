package uwastls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/uwaserver/uwas/internal/config"
)

// writePair writes a generated certificate and key for host under dir and
// returns the two paths plus the certificate's DER leaf for identity checks.
func writePair(t *testing.T, dir, host string) (certPath, keyPath string, leaf []byte) {
	t.Helper()
	cert, certPEM, keyPEM := generateTestCert(t, host)
	certPath = filepath.Join(dir, host+".crt")
	keyPath = filepath.Join(dir, host+".key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, cert.Certificate[0]
}

// served returns the leaf DER GetCertificate hands out for host, or nil.
func served(m *Manager, host string) []byte {
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || c == nil || len(c.Certificate) == 0 {
		return nil
	}
	return c.Certificate[0]
}

func manualDomain(host, certPath, keyPath string) config.Domain {
	return config.Domain{Host: host, SSL: config.SSLConfig{Mode: "manual", Cert: certPath, Key: keyPath}}
}

// F16300: a certificate loaded from ssl.cert/ssl.key lives only in memory
// after LoadManualCerts, and nothing ever removed it. A reload that no longer
// configured it left it served until restart: a domain switched to ssl.mode
// off kept answering TLS with its old certificate, and a host removed and
// later given to another domain handed that domain the previous owner's
// certificate (whose key the previous owner still holds).
func TestManualCertIsDroppedWhenTheConfigNoLongerProvidesIt(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, leaf := writePair(t, dir, "shop.test")

	t.Run("ssl.mode off", func(t *testing.T) {
		m := testManager(t, []config.Domain{manualDomain("shop.test", certPath, keyPath)})
		m.LoadManualCerts()
		if string(served(m, "shop.test")) != string(leaf) {
			t.Fatal("control: the manual certificate is not served after LoadManualCerts")
		}
		m.UpdateDomains([]config.Domain{{Host: "shop.test", SSL: config.SSLConfig{Mode: "off"}}})
		if got := served(m, "shop.test"); got != nil {
			t.Errorf("a domain with ssl.mode off is still served its old manual certificate")
		}
		if m.HasCert("shop.test") {
			t.Errorf("HasCert still reports a certificate for a domain with ssl.mode off")
		}
	})

	t.Run("host removed then reassigned", func(t *testing.T) {
		m := testManager(t, []config.Domain{manualDomain("shop.test", certPath, keyPath)})
		m.LoadManualCerts()
		m.UpdateDomains([]config.Domain{{Host: "other.test", SSL: config.SSLConfig{Mode: "auto"}}})
		m.UpdateDomains([]config.Domain{
			{Host: "other.test", SSL: config.SSLConfig{Mode: "auto"}},
			{Host: "shop.test", SSL: config.SSLConfig{Mode: "auto"}},
		})
		if got := served(m, "shop.test"); string(got) == string(leaf) {
			t.Errorf("a host reassigned after its domain was removed is served the previous owner's certificate")
		}
	})
}

// The cleanup must not take away anything the config still provides, and must
// leave certificates it never loaded alone.
func TestManualCertCleanupKeepsWhatIsStillConfigured(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, leaf := writePair(t, dir, "shop.test")

	t.Run("unchanged manual domain keeps its certificate across a reload", func(t *testing.T) {
		d := manualDomain("shop.test", certPath, keyPath)
		m := testManager(t, []config.Domain{d})
		m.LoadManualCerts()
		m.UpdateDomains([]config.Domain{d})
		if string(served(m, "shop.test")) != string(leaf) {
			t.Error("a manual certificate that is still configured stopped being served")
		}
	})

	t.Run("a replaced pair is applied", func(t *testing.T) {
		d := manualDomain("shop.test", certPath, keyPath)
		m := testManager(t, []config.Domain{d})
		m.LoadManualCerts()
		newCert, newKey, newLeaf := writePair(t, t.TempDir(), "shop.test")
		d.SSL.Cert, d.SSL.Key = newCert, newKey
		m.UpdateDomains([]config.Domain{d})
		if string(served(m, "shop.test")) != string(newLeaf) {
			t.Error("a replaced certificate pair was not applied on reload")
		}
	})

	t.Run("unparsable new files keep the previous certificate (F2770)", func(t *testing.T) {
		d := manualDomain("shop.test", certPath, keyPath)
		m := testManager(t, []config.Domain{d})
		m.LoadManualCerts()
		bad := filepath.Join(t.TempDir(), "bad.crt")
		if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		d.SSL.Cert = bad
		m.UpdateDomains([]config.Domain{d})
		if string(served(m, "shop.test")) != string(leaf) {
			t.Error("a manual domain whose new files do not parse lost its previous certificate")
		}
	})

	t.Run("manual to auto keeps the certificate until ACME replaces it", func(t *testing.T) {
		m := testManager(t, []config.Domain{manualDomain("shop.test", certPath, keyPath)})
		m.LoadManualCerts()
		m.UpdateDomains([]config.Domain{{Host: "shop.test", SSL: config.SSLConfig{Mode: "auto"}}})
		if string(served(m, "shop.test")) != string(leaf) {
			t.Error("switching to auto SSL dropped the certificate before ACME issued a new one")
		}
	})

	t.Run("a certificate that replaced the manual one is not removed with it", func(t *testing.T) {
		m := testManager(t, []config.Domain{manualDomain("shop.test", certPath, keyPath)})
		m.LoadManualCerts()
		// The host's certificate was replaced since the manual load (an
		// upload through the API, or ACME): the pointer in certs is no longer
		// the one the manual pass stored, so that pass must not delete it.
		replacement, _, _ := generateTestCert(t, "shop.test")
		m.RegisterCert("shop.test", replacement)
		m.UpdateDomains([]config.Domain{{Host: "shop.test", SSL: config.SSLConfig{Mode: "off"}}})
		if got := served(m, "shop.test"); string(got) != string(replacement.Certificate[0]) {
			t.Error("the manual cleanup deleted a certificate that had replaced the manual one")
		}
	})

	t.Run("a certificate registered another way is left alone", func(t *testing.T) {
		m := testManager(t, []config.Domain{manualDomain("shop.test", certPath, keyPath)})
		m.LoadManualCerts()
		acme, _, _ := generateTestCert(t, "acme.test")
		m.RegisterCert("acme.test", acme)
		m.UpdateDomains([]config.Domain{
			{Host: "shop.test", SSL: config.SSLConfig{Mode: "off"}},
			{Host: "acme.test", SSL: config.SSLConfig{Mode: "auto"}},
		})
		if got := served(m, "acme.test"); string(got) != string(acme.Certificate[0]) {
			t.Error("the cleanup of manual certificates removed a certificate it never loaded")
		}
	})
}
