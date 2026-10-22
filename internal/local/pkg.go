package local

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0xgitpushpray/php2shell/internal/report"
)

// Overridable in tests.
var (
	goos      = runtime.GOOS
	docDir    = "/usr/share/doc"
	lookPath  = exec.LookPath
	pkgProbes = []func(ctx context.Context, path string, cves []string) *report.Package{dpkgPackage, rpmPackage, apkPackage}
)

// packageFor finds the OS package owning path and checks whether its
// changelog mentions the given CVEs. Distributions backport security fixes
// without changing the upstream version, so this is how a "vulnerable"
// version number can still be a patched build.
func packageFor(ctx context.Context, path string, cves []string) *report.Package {
	if goos != "linux" {
		return nil
	}
	for _, probe := range pkgProbes {
		if p := probe(ctx, path, cves); p != nil {
			return p
		}
	}
	return nil
}

func dpkgPackage(ctx context.Context, path string, cves []string) *report.Package {
	if _, err := lookPath("dpkg-query"); err != nil {
		return nil
	}
	out, err := runCmd(ctx, "dpkg-query", "-S", path)
	if err != nil {
		return nil
	}
	var name string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "diversion ") {
			continue
		}
		if names, _, ok := strings.Cut(line, ": "); ok {
			name = strings.TrimSpace(strings.Split(names, ",")[0])
			break
		}
	}
	if name == "" {
		return nil
	}
	pkg := &report.Package{Manager: "dpkg", Name: name}
	if v, err := runCmd(ctx, "dpkg-query", "-W", "-f=${Version}", name); err == nil {
		pkg.Version = strings.TrimSpace(string(v))
	}
	short, _, _ := strings.Cut(name, ":") // drop the ":amd64" architecture qualifier
	if data, err := readGzip(filepath.Join(docDir, short, "changelog.Debian.gz")); err == nil {
		pkg.ChangelogCVEs = mentioned(data, cves)
	}
	return pkg
}

func rpmPackage(ctx context.Context, path string, cves []string) *report.Package {
	if _, err := lookPath("rpm"); err != nil {
		return nil
	}
	out, err := runCmd(ctx, "rpm", "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path)
	if err != nil {
		return nil
	}
	name, version, ok := strings.Cut(strings.SplitN(string(out), "\n", 2)[0], "\t")
	if !ok || name == "" {
		return nil
	}
	pkg := &report.Package{Manager: "rpm", Name: name, Version: strings.TrimSpace(version)}
	if cl, err := runCmd(ctx, "rpm", "-q", "--changelog", name); err == nil {
		pkg.ChangelogCVEs = mentioned(cl, cves)
	}
	return pkg
}

func apkPackage(ctx context.Context, path string, _ []string) *report.Package {
	if _, err := lookPath("apk"); err != nil {
		return nil
	}
	out, err := runCmd(ctx, "apk", "info", "--who-owns", path)
	if err != nil {
		return nil
	}
	_, owner, ok := strings.Cut(strings.TrimSpace(string(out)), " is owned by ")
	if !ok {
		return nil
	}
	// "php83-fpm-8.3.12-r0" -> name "php83-fpm", version "8.3.12-r0". apk
	// ships no changelogs, so backports cannot be confirmed here.
	pkg := &report.Package{Manager: "apk", Name: owner}
	if parts := strings.Split(owner, "-"); len(parts) > 2 {
		pkg.Name = strings.Join(parts[:len(parts)-2], "-")
		pkg.Version = strings.Join(parts[len(parts)-2:], "-")
	}
	return pkg
}

func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, 64<<20))
}

func mentioned(data []byte, ids []string) []string {
	var out []string
	for _, id := range ids {
		if bytes.Contains(data, []byte(id)) {
			out = append(out, id)
		}
	}
	return out
}
