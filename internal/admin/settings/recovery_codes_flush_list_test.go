package settings

import (
	"strings"
	"testing"
)

// TestMaskRecoveryCodesFlushSequence pins the YAML form where the sequence
// items sit at the same indent as their key ("recovery_codes:\n- hash"). The
// raw config GET masks recovery_codes, but only items indented deeper than the
// key were masked, so a hand-written file in this (valid) layout leaked every
// stored recovery-code hash, and a save of the masked view could not restore
// them from disk.
func TestMaskRecoveryCodesFlushSequence(t *testing.T) {
	const flush = "admin:\n  recovery_codes:\n  - hash-one\n  - hash-two\n  listen: x\n"
	const indented = "admin:\n  recovery_codes:\n    - hash-one\n    - hash-two\n  listen: x\n"

	// Control: the indented layout (what yaml.v3 writes) is masked.
	if got := maskYAMLListValue(indented, "recovery_codes"); strings.Contains(got, "hash-") {
		t.Fatalf("control: indented list not masked:\n%s", got)
	}

	got := maskYAMLListValue(flush, "recovery_codes")
	if strings.Contains(got, "hash-") {
		t.Errorf("EXPECTED: no recovery-code hash in the masked view\nACTUAL:\n%s", got)
	}
	if !strings.Contains(got, "listen: x") {
		t.Errorf("sibling key lost:\n%s", got)
	}

	// Round trip: saving the masked view restores the on-disk items.
	back := unmaskYAMLListValue(got, flush, "recovery_codes")
	if !strings.Contains(back, "- hash-one") || !strings.Contains(back, "- hash-two") || strings.Contains(back, "********") {
		t.Errorf("EXPECTED: masked items restored from disk\nACTUAL:\n%s", back)
	}
}
