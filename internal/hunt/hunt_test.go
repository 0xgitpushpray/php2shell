package hunt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/report"
)

// j joins fragments. Test samples are assembled at runtime so this source
// file never contains a complete web-shell pattern; antivirus scanners
// would otherwise quarantine the repository on checkout.
func j(parts ...string) string { return strings.Join(parts, "") }

func write(t *testing.T, root, rel, content string, mod time.Time) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Skipf("cannot write sample %s (blocked by antivirus?): %v", rel, err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestHunt(t *testing.T) {
	root := t.TempDir()
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	php := "<?" + "php "

	write(t, root, "index.php", php+"require 'app.php';", old)
	write(t, root, "decode.php", php+j("$x = ev", "al(gzinf", "late('abc'));"), old)
	write(t, root, "dyn.php", php+j("$_REQ", "UEST['f']('a');"), old)
	write(t, root, "marker.php", php+j("// Files", "Man"), old)
	write(t, root, "wp-content/uploads/2026/10/x.php", php+"echo 1;", old)
	write(t, root, "wp-content/uploads/index.php", php+"// Silence is golden.", old)
	write(t, root, "logo.png", "\x89PNG...."+php+"echo 1; ?>", old)
	write(t, root, ".cache.php", php+"echo 1;", old)
	write(t, root, "deploy.php", php+"echo 'new release';", recent)
	write(t, root, "node_modules/pkg/skip.php", php+j("ev", "al(gzinf", "late('abc'));"), old)

	findings, notes, err := Run(context.Background(), Options{
		Roots: []string{root}, Since: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{} // rule@file -> severity
	for _, f := range findings {
		rel, _ := filepath.Rel(root, f.Path)
		got[f.Rule+"@"+filepath.ToSlash(rel)] = f.Severity
	}
	want := map[string]string{
		"eval-decoded-payload@decode.php":                    report.High,
		"dynamic-call-request-input@dyn.php":                 report.High,
		"known-webshell@marker.php":                          report.High,
		"php-in-upload-dir@wp-content/uploads/2026/10/x.php": report.Medium,
		"php-in-image@logo.png":                              report.High,
		"hidden-php-file@.cache.php":                         report.Medium,
		"recently-modified@deploy.php":                       report.Low,
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("missing %s (%s); got %v", k, sev, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected findings: got %d %v, want %d", len(got), got, len(want))
	}
	if findings[0].Severity != report.High {
		t.Error("findings must be sorted by severity")
	}
	if len(notes) == 0 {
		t.Error("expected a summary note")
	}
}

// TestContentRules checks every rule in memory; some samples are too close to
// real malware to write to disk on machines with real-time antivirus.
func TestContentRules(t *testing.T) {
	samples := map[string]string{
		"eval-decoded-payload":          j("@ev", "al( base64", "_decode($p));"),
		"exec-request-input":            j("echo pass", "thru(", "$_SER", "VER['HTTP_X_T']);"),
		"dynamic-call-request-input":    j("@$_CO", "OKIE['f']($a);"),
		"create-function-request-input": j("$f = create", "_function('', $_P", "OST['c']);"),
		"known-webshell":                j("<title>b37", "4k</title>"),
		"preg-replace-eval":             j("preg", "_replace('/.*/e', $r, '');"),
		"hex-obfuscation":               strings.Repeat(`\x41`, 12),
		"encoded-blob":                  strings.Repeat("QUJD", 300),
	}
	for _, r := range contentRules {
		s, ok := samples[r.id]
		if !ok {
			t.Errorf("rule %s has no test sample", r.id)
			continue
		}
		if !r.re.MatchString(s) {
			t.Errorf("rule %s does not match its sample %q", r.id, s)
		}
	}
	clean := []string{
		"$value = $_GET['page'] ?? 'home';",
		"echo htmlspecialchars($_POST['name']);",
		"$data = base64_decode($token);",
		"preg_replace('/a/i', 'b', $s);",
	}
	for _, s := range clean {
		for _, r := range contentRules {
			if r.re.MatchString(s) {
				t.Errorf("rule %s false positive on %q", r.id, s)
			}
		}
	}
}

func TestHuntMissingRoot(t *testing.T) {
	_, _, err := Run(context.Background(), Options{Roots: []string{filepath.Join(t.TempDir(), "nope")}})
	if err == nil {
		t.Fatal("expected an error for a missing root")
	}
}
