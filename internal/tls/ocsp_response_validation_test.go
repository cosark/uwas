package uwastls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/uwaserver/uwas/internal/logger"
)

func f19300Cert(t *testing.T, mode *atomic.Int32) *tls.Certificate {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "f19300 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	issuer, _ := x509.ParseCertificate(caDER)
	leafSerial := big.NewInt(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tpl := ocsp.Response{Status: ocsp.Good, SerialNumber: leafSerial,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(24 * time.Hour)}
		switch mode.Load() {
		case 3: // no NextUpdate: newer information is always available
			tpl.NextUpdate = time.Time{}
		case 1: // another certificate's response
			tpl.SerialNumber = big.NewInt(999)
		case 2: // replayed response that ran out
			tpl.ThisUpdate, tpl.NextUpdate = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
		}
		resp, err := ocsp.CreateResponse(issuer, issuer, tpl, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "f.example"}, DNSNames: []string{"f.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour),
		OCSPServer: []string{srv.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, issuer, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
}

// F19300: the OCSP responder URL is plain HTTP and a response only has to be
// signed by the issuer to parse. A response for another certificate, or one
// past its NextUpdate, used to be stapled as this certificate's own.
func TestFetchOCSPRejectsForeignAndExpiredResponses(t *testing.T) {
	m := &Manager{logger: logger.New("error", "text")}
	var mode atomic.Int32
	cert := f19300Cert(t, &mode)

	for _, c := range []struct {
		name    string
		mode    int32
		stapled bool
	}{
		{"matching current response", 0, true},
		{"no NextUpdate is still current", 3, true},
		{"response for another serial", 1, false},
		{"expired response", 2, false},
	} {
		mode.Store(c.mode)
		if got := m.fetchOCSP(t.Context(), cert, "f.example") != nil; got != c.stapled {
			t.Errorf("%s: stapled=%v, want %v", c.name, got, c.stapled)
		}
	}
}
