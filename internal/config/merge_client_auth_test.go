package config

import "testing"

// F16701: an Update (PATCH) that sets ssl.client_auth / ssl.client_ca must keep
// them; MergeDomain used to drop both, so the admin API accepted the change and
// silently left mutual TLS off.
func TestMergeDomainKeepsClientCertSettings(t *testing.T) {
	cur := Domain{Host: "a.example", SSL: SSLConfig{Mode: "off"}}
	patch := Domain{SSL: SSLConfig{Mode: "off", ClientAuth: "require", ClientCA: "/etc/ssl/ca.pem"}}
	got := MergeDomain(cur, patch, DomainPatchFields{HasSSL: true}, false)
	if got.SSL.ClientAuth != "require" || got.SSL.ClientCA != "/etc/ssl/ca.pem" {
		t.Fatalf("client_auth/client_ca dropped by MergeDomain: %+v", got.SSL)
	}
}

// A patch that only adds client_auth cannot be judged alone: it is valid when a
// CA is already stored on the domain and invalid when there is none. The
// merged domain is what must be checked (F16701).
func TestClientAuthIsJudgedOnTheMergedDomain(t *testing.T) {
	patch := Domain{SSL: SSLConfig{Mode: "off", ClientAuth: "require"}}
	fields := DomainPatchFields{HasSSL: true}

	withCA := Domain{Host: "a.example", SSL: SSLConfig{Mode: "off", ClientCA: "/etc/ssl/ca.pem"}}
	if err := ValidateClientAuthCA(MergeDomain(withCA, patch, fields, false).SSL); err != nil {
		t.Errorf("client_auth added next to a stored CA was refused: %v", err)
	}

	noCA := Domain{Host: "a.example", SSL: SSLConfig{Mode: "off"}}
	if err := ValidateClientAuthCA(MergeDomain(noCA, patch, fields, false).SSL); err == nil {
		t.Error("client_auth require with no CA anywhere was accepted: the domain would serve anonymous clients")
	}

	for _, ca := range []string{"none", ""} {
		if err := ValidateClientAuthCA(SSLConfig{ClientAuth: ca}); err != nil {
			t.Errorf("client_auth %q needs no CA: %v", ca, err)
		}
	}
}
