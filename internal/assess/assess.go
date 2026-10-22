// Package assess turns a PHP version string into a PHP2Shell verdict.
package assess

import (
	"fmt"
	"strings"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/phpver"
)

// Status is the outcome of a check.
type Status string

const (
	// Patched: the version includes the upstream fix.
	Patched Status = "patched"
	// VendorPatched: the upstream version is affected, but the installed
	// package's changelog shows the vendor backported the fix.
	VendorPatched Status = "vendor-patched"
	// Vulnerable: a supported branch older than its fixed release.
	Vulnerable Status = "vulnerable"
	// EOL: an end-of-life branch with no official fix.
	EOL Status = "eol"
	// RestartRequired: the binary on disk is fixed, but running workers
	// still execute the old, vulnerable code.
	RestartRequired Status = "restart-required"
	// Unknown: the version could not be determined or judged.
	Unknown Status = "unknown"
)

// ExitCode maps a status to the CLI exit code: 0 safe, 1 at risk, 3 unknown.
func (s Status) ExitCode() int {
	switch s {
	case Patched, VendorPatched:
		return 0
	case Unknown:
		return 3
	default:
		return 1
	}
}

// Confidence says how much the verdict can be trusted.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Verdict is the judgement for one PHP version.
type Verdict struct {
	Status      Status     `json:"status"`
	Confidence  Confidence `json:"confidence"`
	PHPVersion  string     `json:"php_version,omitempty"`
	FixedIn     string     `json:"fixed_in,omitempty"`
	Reason      string     `json:"reason"`
	Remediation string     `json:"remediation,omitempty"`
}

// UnknownVerdict returns an Unknown verdict with the given reason.
func UnknownVerdict(reason string) Verdict {
	return Verdict{Status: Unknown, Confidence: Low, Reason: reason}
}

// UpgradeAdvice is the generic remediation for versions without an in-branch fix.
func UpgradeAdvice(a *advisory.Advisory) string {
	return fmt.Sprintf("Upgrade to a supported release (%s or later in its branch) and restart every PHP worker.",
		joinOr(a.FixedReleases()))
}

// Classify judges a raw PHP version string against the advisory.
func Classify(a *advisory.Advisory, raw string) Verdict {
	v, err := phpver.Parse(raw)
	if err != nil {
		out := UnknownVerdict(fmt.Sprintf("unrecognized PHP version %q", strings.TrimSpace(raw)))
		out.PHPVersion = strings.TrimSpace(raw)
		return out
	}
	out := Verdict{PHPVersion: v.String(), Confidence: High}

	if v.Prerelease() {
		out.Status, out.Confidence = Unknown, Low
		out.Reason = fmt.Sprintf("PHP %s is a pre-release build; compare its source against the fix manually", v)
		out.Remediation = UpgradeAdvice(a)
		return out
	}

	b, ok := a.Lookup(v.Major, v.Minor)
	if !ok {
		newest := a.Newest()
		first, _ := phpver.Parse(a.FirstAffected)
		nv, _ := phpver.Parse(newest.Branch + ".0")
		switch {
		case phpver.Compare(phpver.Version{Major: v.Major, Minor: v.Minor}, nv) > 0:
			out.Status, out.Confidence = Unknown, Medium
			out.Reason = fmt.Sprintf("PHP %s is newer than the advisory data (revision %s); run `php2shell update`", v, a.Revision)
		case phpver.Compare(v, first) < 0:
			out.Status, out.Confidence = EOL, Medium
			out.Reason = fmt.Sprintf("PHP %s predates the first affected release (%s) but has been end-of-life for over a decade", v, a.FirstAffected)
			out.Remediation = UpgradeAdvice(a)
		default:
			out.Status, out.Confidence = Unknown, Low
			out.Reason = fmt.Sprintf("PHP %s is not a known release branch", v.Branch())
		}
		return out
	}

	if b.EOL {
		out.Status = EOL
		out.Reason = fmt.Sprintf("PHP %s is end-of-life and no official PHP release fixes %s", b.Branch, a.Name)
		if b.SourceBackport {
			out.Reason += " (a minimal source backport exists for self-built PHP)"
		}
		if v.VendorBuild() {
			out.Confidence = Medium
			out.Reason += "; this is a vendor build, so check the vendor's advisory or run `php2shell local` on the server"
		}
		out.Remediation = UpgradeAdvice(a)
		return out
	}

	fixed := b.FixedVersion()
	out.FixedIn = fixed.String()
	if phpver.Compare(v, fixed) >= 0 {
		out.Status = Patched
		out.Reason = fmt.Sprintf("PHP %s includes the fix (first fixed in %s)", v, fixed)
		return out
	}
	out.Status = Vulnerable
	out.Reason = fmt.Sprintf("PHP %s is older than %s, the first %s release with the fix", v, fixed, b.Branch)
	out.Remediation = fmt.Sprintf("Upgrade to PHP %s or later, then restart every PHP worker (php-fpm, Apache, LiteSpeed, FrankenPHP).", fixed)
	if v.VendorBuild() {
		out.Confidence = Low
		out.Reason += "; this is a vendor build that may carry a backported fix, so run `php2shell local` on the server to check the package"
	}
	return out
}

func joinOr(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}
