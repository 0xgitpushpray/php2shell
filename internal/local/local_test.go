package local

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
	"github.com/0xgitpushpray/php2shell/internal/report"
)

func adv(t *testing.T) *advisory.Advisory {
	t.Helper()
	a, err := advisory.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fakeBinary writes a file that looks like a PHP build: junk around the
// compiled-in X-Powered-By constant.
func fakeBinary(t *testing.T, dir, name, version string) string {
	t.Helper()
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 0}, 1000))
	if version != "" {
		b.WriteString("X-Powered-By: PHP/" + version + "\x00")
	}
	b.Write(bytes.Repeat([]byte{0}, 1000))
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func stubCmd(t *testing.T, fn func(name string, args ...string) ([]byte, error)) {
	t.Helper()
	orig := runCmd
	runCmd = func(_ context.Context, name string, args ...string) ([]byte, error) { return fn(name, args...) }
	t.Cleanup(func() { runCmd = orig })
}

func TestScanReader(t *testing.T) {
	chunk := 1 << 20
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"simple", []byte("abc\x00X-Powered-By: PHP/8.3.12\x00def"), "8.3.12"},
		{"vendor suffix", []byte("X-Powered-By: PHP/8.1.2-1ubuntu2.14\x00"), "8.1.2-1ubuntu2.14"},
		{"at end of file", []byte("X-Powered-By: PHP/8.4.27"), "8.4.27"},
		{"false hit first", []byte("X-Powered-By: PHP/%s\x00 X-Powered-By: PHP/8.2.1\x00"), "8.2.1"},
		{"across chunk boundary", append(bytes.Repeat([]byte{'a'}, chunk-7), []byte("X-Powered-By: PHP/8.5.11\x00")...), "8.5.11"},
		{"version across boundary", append(bytes.Repeat([]byte{'a'}, chunk-20), []byte("X-Powered-By: PHP/8.5.11-1+deb12u1\x00")...), "8.5.11-1+deb12u1"},
	}
	for _, tt := range tests {
		got, err := scanReader(bytes.NewReader(tt.data))
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}
	if _, err := scanReader(strings.NewReader("no marker here")); !errors.Is(err, ErrNoBuildString) {
		t.Errorf("expected ErrNoBuildString, got %v", err)
	}
}

func TestNameRe(t *testing.T) {
	match := []string{"php", "php8.3", "php83", "php-fpm", "php-fpm8.3", "php-fpm83", "php8.3-fpm", "php-cgi.exe",
		"php.exe", "php-win.exe", "lsphp", "lsphp83", "frankenphp", "libphp.so", "libphp8.3.so", "mod_php83.so"}
	skip := []string{"phpize", "phpize8.3", "php-config", "phpunit", "phpstan", "php.ini", "php8ts.dll", "phar"}
	for _, n := range match {
		if !nameRe.MatchString(n) {
			t.Errorf("%q should match", n)
		}
	}
	for _, n := range skip {
		if nameRe.MatchString(n) {
			t.Errorf("%q should not match", n)
		}
	}
}

func TestDiscoverExtraDir(t *testing.T) {
	dir := t.TempDir()
	php := fakeBinary(t, dir, "php8.3", "8.3.12")
	fakeBinary(t, dir, "phpize", "8.3.12")
	var found []string
	for _, c := range discover([]string{dir}, procInfo{}) {
		found = append(found, c.path)
	}
	real, _ := filepath.EvalSymlinks(php)
	if !containsPath(found, real) {
		t.Errorf("php8.3 not discovered in %v", found)
	}
	for _, f := range found {
		if filepath.Base(f) == "phpize" {
			t.Errorf("phpize must not be discovered")
		}
	}
}

func containsPath(list []string, p string) bool {
	for _, x := range list {
		if strings.EqualFold(x, p) {
			return true
		}
	}
	return false
}

func TestInspectBuildString(t *testing.T) {
	stubCmd(t, func(string, ...string) ([]byte, error) { return nil, errors.New("not executed") })
	p := fakeBinary(t, t.TempDir(), "php-fpm8.3", "8.3.12")
	res := inspect(context.Background(), adv(t), &candidate{path: p}, Options{NoPackages: true})
	if res.Status != assess.Vulnerable || res.SAPI != "php-fpm" || res.Source != "build string" {
		t.Fatalf("got %s sapi=%s source=%s (%s)", res.Status, res.SAPI, res.Source, res.Reason)
	}
}

func TestInspectExecFallbackAndINIHints(t *testing.T) {
	stubCmd(t, func(_ string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "-i" {
			return []byte("session.upload_progress.enabled => On => On\nmemory_limit => 128M => 128M\n"), nil
		}
		return []byte("PHP 8.2.10 (cli) (built: Sep  1 2023)\nCopyright (c) The PHP Group\n"), nil
	})
	p := fakeBinary(t, t.TempDir(), "php", "") // no build string: wrapper script
	res := inspect(context.Background(), adv(t), &candidate{path: p}, Options{NoPackages: true})
	if res.Status != assess.Vulnerable || res.PHPVersion != "8.2.10" || res.Source != "`-v` output" {
		t.Fatalf("got %s %q via %q (%s)", res.Status, res.PHPVersion, res.Source, res.Reason)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "session.upload_progress.enabled") {
		t.Errorf("notes = %v", res.Notes)
	}

	res = inspect(context.Background(), adv(t), &candidate{path: p}, Options{NoPackages: true, NoExec: true})
	if res.Status != assess.Unknown {
		t.Errorf("--no-exec without build string: got %s", res.Status)
	}
}

func TestVendorPatched(t *testing.T) {
	origGOOS, origProbes := goos, pkgProbes
	t.Cleanup(func() { goos, pkgProbes = origGOOS, origProbes })
	goos = "linux"
	pkgProbes = []func(context.Context, string, []string) *report.Package{
		func(_ context.Context, _ string, cves []string) *report.Package {
			return &report.Package{Manager: "dpkg", Name: "php8.1-fpm", Version: "8.1.2-1ubuntu2.22", ChangelogCVEs: cves}
		},
	}
	p := fakeBinary(t, t.TempDir(), "php-fpm8.1", "8.1.2-1ubuntu2.22")
	res := inspect(context.Background(), adv(t), &candidate{path: p}, Options{NoExec: true})
	if res.Status != assess.VendorPatched || res.Package == nil {
		t.Fatalf("got %s (%s)", res.Status, res.Reason)
	}
}

func TestDpkgPackage(t *testing.T) {
	origLook, origDoc := lookPath, docDir
	t.Cleanup(func() { lookPath, docDir = origLook, origDoc })
	lookPath = func(string) (string, error) { return "/usr/bin/dpkg-query", nil }
	docDir = t.TempDir()
	os.MkdirAll(filepath.Join(docDir, "php8.3-fpm"), 0o755)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("php8.3 (8.3.6-0ubuntu0.24.04.5) noble-security\n  * SECURITY UPDATE: CVE-2026-109618 and CVE-2026-109619\n"))
	zw.Close()
	os.WriteFile(filepath.Join(docDir, "php8.3-fpm", "changelog.Debian.gz"), gz.Bytes(), 0o644)

	stubCmd(t, func(_ string, args ...string) ([]byte, error) {
		if args[0] == "-S" {
			return []byte("diversion by x from: /y\nphp8.3-fpm:amd64: /usr/sbin/php-fpm8.3\n"), nil
		}
		return []byte("8.3.6-0ubuntu0.24.04.5"), nil
	})
	p := dpkgPackage(context.Background(), "/usr/sbin/php-fpm8.3", adv(t).CVEIDs())
	if p == nil || p.Name != "php8.3-fpm:amd64" || p.Version != "8.3.6-0ubuntu0.24.04.5" || len(p.ChangelogCVEs) != 2 {
		t.Fatalf("got %+v", p)
	}
}

func TestRpmAndApkPackages(t *testing.T) {
	origLook := lookPath
	t.Cleanup(func() { lookPath = origLook })
	lookPath = func(string) (string, error) { return "/bin/x", nil }
	stubCmd(t, func(name string, args ...string) ([]byte, error) {
		switch {
		case name == "rpm" && args[0] == "-qf":
			return []byte("php-fpm\t8.2.25-2.el9_5\n"), nil
		case name == "rpm":
			return []byte("* Tue Oct 20 2026 - 8.2.25-2\n- fix CVE-2026-109618\n"), nil
		case name == "apk":
			return []byte("/usr/sbin/php-fpm83 is owned by php83-fpm-8.3.12-r0\n"), nil
		}
		return nil, errors.New("unexpected")
	})
	cves := adv(t).CVEIDs()
	if p := rpmPackage(context.Background(), "/usr/sbin/php-fpm", cves); p == nil || p.Version != "8.2.25-2.el9_5" || len(p.ChangelogCVEs) != 1 {
		t.Errorf("rpm: %+v", p)
	}
	if p := apkPackage(context.Background(), "/usr/sbin/php-fpm83", cves); p == nil || p.Name != "php83-fpm" || p.Version != "8.3.12-r0" {
		t.Errorf("apk: %+v", p)
	}
}

func TestRestartRequired(t *testing.T) {
	dir := t.TempDir()
	onDisk := fakeBinary(t, dir, "php-fpm8.3", "8.3.36")
	oldBuild := fakeBinary(t, dir, "old-exe", "8.3.12") // stands in for /proc/<pid>/exe
	c := &candidate{path: onDisk, proc: &procEntry{pids: []int{10, 11}, stale: []int{10, 11}, staleExe: oldBuild}}
	res := inspect(context.Background(), adv(t), c, Options{NoExec: true, NoPackages: true})
	if res.Status != assess.RestartRequired || !strings.Contains(res.Reason, "PHP 8.3.12") {
		t.Fatalf("got %s (%s)", res.Status, res.Reason)
	}
}

func TestGoneBinary(t *testing.T) {
	old := fakeBinary(t, t.TempDir(), "exe", "8.4.20")
	c := &candidate{path: "/usr/sbin/php-fpm8.4", gone: true, proc: &procEntry{pids: []int{42}, stale: []int{42}, staleExe: old}}
	res := inspect(context.Background(), adv(t), c, Options{})
	if res.Status != assess.Vulnerable || len(res.Notes) == 0 {
		t.Fatalf("got %s notes=%v", res.Status, res.Notes)
	}
}

func TestSAPI(t *testing.T) {
	want := map[string]string{"php": "cli", "php-fpm8.3": "php-fpm", "php-cgi.exe": "php-cgi",
		"libphp8.3.so": "apache mod_php", "lsphp": "litespeed", "frankenphp": "frankenphp"}
	for name, sapi := range want {
		if got := sapiOf("/x/" + name); got != sapi {
			t.Errorf("sapiOf(%s) = %s, want %s", name, got, sapi)
		}
	}
}
