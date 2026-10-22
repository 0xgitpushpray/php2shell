package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/assess"
)

func sample() *Report {
	r := &Report{
		Tool: "php2shell", Version: "test", Command: "check",
		Advisory: AdvisoryInfo{Name: "PHP2Shell", Revision: "2026-10-22", CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"}},
		Results: []Result{
			{Kind: "url", Target: "https://a.example", Verdict: assess.Verdict{Status: assess.Vulnerable, Confidence: assess.High, PHPVersion: "8.3.12", FixedIn: "8.3.36", Reason: "old", Remediation: "upgrade"}},
			{Kind: "url", Target: "https://b.example", Verdict: assess.Verdict{Status: assess.Patched, Confidence: assess.High, PHPVersion: "8.4.27", Reason: "ok"}},
			{Kind: "url", Target: "https://c.example", Verdict: assess.Verdict{Status: assess.Unknown, Confidence: assess.Low, Reason: "hidden"}},
		},
	}
	r.Finalize()
	return r
}

func TestFinalize(t *testing.T) {
	r := sample()
	if r.ExitCode != 1 || r.Summary["vulnerable"] != 1 || r.Summary["patched"] != 1 || r.Summary["unknown"] != 1 {
		t.Fatalf("exit=%d summary=%v", r.ExitCode, r.Summary)
	}
	r.Results = r.Results[1:]
	r.Finalize()
	if r.ExitCode != 3 {
		t.Errorf("unknown should win over patched: %d", r.ExitCode)
	}
	r.Results = nil
	r.Findings = []Finding{{Severity: Low, Rule: "recently-modified", Path: "/x"}}
	r.Finalize()
	if r.ExitCode != 0 {
		t.Errorf("low findings alone should exit 0: %d", r.ExitCode)
	}
	r.Findings = append(r.Findings, Finding{Severity: High, Rule: "php-in-image", Path: "/y"})
	r.Finalize()
	if r.ExitCode != 1 {
		t.Errorf("high findings should exit 1: %d", r.ExitCode)
	}
}

func TestFormats(t *testing.T) {
	r := sample()
	for _, f := range Formats {
		var b bytes.Buffer
		if err := Write(&b, r, f, Options{}); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out := b.String()
		switch f {
		case "text":
			for _, s := range []string{"VULNERABLE", "PATCHED", "UNKNOWN", "→ upgrade", "Summary: 1 vulnerable · 1 unknown · 1 patched"} {
				if !strings.Contains(out, s) {
					t.Errorf("text output missing %q:\n%s", s, out)
				}
			}
		case "json":
			var back Report
			if err := json.Unmarshal(b.Bytes(), &back); err != nil || back.Results[0].Status != assess.Vulnerable || back.ExitCode != 1 {
				t.Errorf("json round trip: %v %+v", err, back)
			}
			if !strings.Contains(out, `"php_version": "8.3.12"`) {
				t.Error("verdict fields must be flattened into each result")
			}
		case "csv":
			if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 4 || !strings.HasPrefix(lines[0], "kind,target,status") {
				t.Errorf("csv:\n%s", out)
			}
		case "sarif":
			var log sarifLog
			if err := json.Unmarshal(b.Bytes(), &log); err != nil || log.Version != "2.1.0" || len(log.Runs[0].Results) != 2 {
				t.Errorf("sarif: %v %s", err, out)
			}
		}
	}
	if err := Write(&bytes.Buffer{}, r, "xml", Options{}); err == nil {
		t.Error("unknown format should fail")
	}
}

func TestQuietText(t *testing.T) {
	r := &Report{Tool: "php2shell", Results: []Result{{Target: "x", Verdict: assess.Verdict{Status: assess.Patched}}}}
	r.Finalize()
	var b bytes.Buffer
	writeText(&b, r, Options{Quiet: true})
	if !strings.Contains(b.String(), "All 1 targets are patched") {
		t.Errorf("quiet output:\n%s", b.String())
	}
}

func TestFindingsText(t *testing.T) {
	r := &Report{Tool: "php2shell", Findings: []Finding{{Severity: High, Rule: "php-in-image", Path: "/var/www/a.png", Detail: "image file contains PHP code", Modified: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}}}
	r.Finalize()
	var b bytes.Buffer
	writeText(&b, r, Options{})
	if !strings.Contains(b.String(), "HIGH") || !strings.Contains(b.String(), "/var/www/a.png") {
		t.Errorf("findings output:\n%s", b.String())
	}
}

func TestToURI(t *testing.T) {
	if got := toURI("https://x.example/a"); got != "https://x.example/a" {
		t.Error(got)
	}
	if got := toURI("rel/path.php"); got != "rel/path.php" {
		t.Error(got)
	}
}
