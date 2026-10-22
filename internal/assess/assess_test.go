package assess

import (
	"testing"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
)

func TestClassify(t *testing.T) {
	a, err := advisory.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		version    string
		status     Status
		confidence Confidence
		fixedIn    string
	}{
		{"8.5.11", Vulnerable, High, "8.5.12"},
		{"8.5.12", Patched, High, "8.5.12"},
		{"8.4.26", Vulnerable, High, "8.4.27"},
		{"8.4.27", Patched, High, "8.4.27"},
		{"8.3.12", Vulnerable, High, "8.3.36"},
		{"8.3.36", Patched, High, "8.3.36"},
		{"8.3.40", Patched, High, "8.3.36"},
		{"8.2.34", Vulnerable, High, "8.2.35"},
		{"8.2.35", Patched, High, "8.2.35"},
		{"8.1.34", EOL, High, ""},
		{"7.4.33", EOL, High, ""},
		{"5.6.40", EOL, High, ""},
		{"5.3.29", EOL, Medium, ""},
		{"8.1.2-1ubuntu2.14", EOL, Medium, ""},
		{"8.3.6-0ubuntu0.24.04.2", Vulnerable, Low, "8.3.36"},
		{"8.3.36-1+deb12u1", Patched, High, "8.3.36"},
		{"8.5.12RC1", Unknown, Low, ""},
		{"8.6.0-dev", Unknown, Low, ""},
		{"8.6.0", Unknown, Medium, ""},
		{"9.0.1", Unknown, Medium, ""},
		{"6.0.0", Unknown, Low, ""},
		{"garbage", Unknown, Low, ""},
	}
	for _, tt := range tests {
		got := Classify(a, tt.version)
		if got.Status != tt.status || got.Confidence != tt.confidence || got.FixedIn != tt.fixedIn {
			t.Errorf("Classify(%q) = %s/%s fixed=%q (%s); want %s/%s fixed=%q",
				tt.version, got.Status, got.Confidence, got.FixedIn, got.Reason, tt.status, tt.confidence, tt.fixedIn)
		}
		if got.Reason == "" {
			t.Errorf("Classify(%q) has no reason", tt.version)
		}
		if got.Status.ExitCode() == 1 && got.Remediation == "" {
			t.Errorf("Classify(%q) is at risk but has no remediation", tt.version)
		}
	}
}

func TestExitCodes(t *testing.T) {
	want := map[Status]int{Patched: 0, VendorPatched: 0, Vulnerable: 1, EOL: 1, RestartRequired: 1, Unknown: 3}
	for s, code := range want {
		if s.ExitCode() != code {
			t.Errorf("%s.ExitCode() = %d, want %d", s, s.ExitCode(), code)
		}
	}
}

func TestUpgradeAdvice(t *testing.T) {
	a, _ := advisory.Embedded()
	want := "Upgrade to a supported release (8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later in its branch) and restart every PHP worker."
	if got := UpgradeAdvice(a); got != want {
		t.Errorf("UpgradeAdvice = %q", got)
	}
}
