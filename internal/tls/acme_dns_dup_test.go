package uwastls

import (
	"fmt"
	"testing"

	"github.com/uwaserver/uwas/internal/dnsmanager"
)

// uniqueIDProvider is a mockDNSProvider that hands out unique record IDs.
type uniqueIDProvider struct {
	*mockDNSProvider
	n int
}

func (u *uniqueIDProvider) CreateRecord(zoneID string, rec dnsmanager.Record) (*dnsmanager.Record, error) {
	u.n++
	rec.ID = fmt.Sprintf("rec-%d", u.n)
	u.records[zoneID] = append(u.records[zoneID], rec)
	return &rec, nil
}

// TestDNSChallengeRetryLeavesNoDuplicateTXT: a retried Present must not stack
// identical TXT records and Cleanup must leave no _acme-challenge TXT behind.
func TestDNSChallengeRetryLeavesNoDuplicateTXT(t *testing.T) {
	mp := &uniqueIDProvider{mockDNSProvider: &mockDNSProvider{
		zones:   []dnsmanager.Zone{{ID: "z1", Name: "example.com"}},
		records: make(mockZoneRecords),
	}}
	p := &acmeDNSProvider{dp: mp}
	d := "_acme-challenge.example.com"
	for i := 0; i < 2; i++ {
		if err := p.PresentDNSChallenge(d, "t", "ka"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(mp.records["z1"]); n != 1 {
		t.Fatalf("duplicate TXT after retry: %d records", n)
	}
	// Pre-existing duplicates (e.g. from an older run) are all removed.
	mp.records["z1"] = append(mp.records["z1"], mp.records["z1"][0])
	mp.records["z1"][1].ID = "dup"
	if err := p.CleanupDNSChallenge(d, "t", "ka"); err != nil {
		t.Fatal(err)
	}
	if n := len(mp.records["z1"]); n != 0 {
		t.Fatalf("leftover TXT after cleanup: %d", n)
	}
	// A different keyAuth (wildcard + apex) is untouched by cleanup.
	_ = p.PresentDNSChallenge(d, "t", "other")
	_ = p.PresentDNSChallenge(d, "t", "ka")
	_ = p.CleanupDNSChallenge(d, "t", "ka")
	if n := len(mp.records["z1"]); n != 1 {
		t.Fatalf("sibling challenge record removed: %d", n)
	}
}
