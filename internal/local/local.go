// Package local inventories every PHP installation on this machine (CLI,
// php-fpm, php-cgi, Apache mod_php, LiteSpeed, FrankenPHP, control-panel and
// SCL builds) and judges each one against the PHP2Shell advisory.
package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
	"github.com/0xgitpushpray/php2shell/internal/phpver"
	"github.com/0xgitpushpray/php2shell/internal/report"
)

// Options configure the local inventory.
type Options struct {
	Paths       []string // extra binaries or directories to inspect
	NoExec      bool     // never execute PHP binaries
	NoPackages  bool     // skip OS package and changelog checks
	NoProcesses bool     // skip running-process checks
}

// nameRe matches PHP executables and Apache modules, e.g. php, php8.3,
// php83, php-fpm8.3, php-cgi.exe, lsphp, frankenphp, libphp8.3.so, mod_php83.so.
var nameRe = regexp.MustCompile(`(?i)^((php|php-fpm|php-cgi|php-win|lsphp|frankenphp)[\d.]*|php[\d.]*-(fpm|cgi))(\.exe)?$|^(libphp|mod_php)[\d.]*\.so$`)

var execVersionRe = regexp.MustCompile(`(?m)^PHP (\d+\.\d+\.\d+[^\s,;()]*)`)

// runCmd runs a command with a timeout. Overridable in tests.
var runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

type candidate struct {
	path    string // resolved path
	aliases []string
	gone    bool // deleted from disk; only running processes still use it
	proc    *procEntry
}

// Run inventories and judges every PHP installation it can find.
func Run(ctx context.Context, a *advisory.Advisory, opt Options) ([]report.Result, []string) {
	var procs procInfo
	var notes []string
	if !opt.NoProcesses {
		procs = scanProcesses()
		if !procs.supported {
			notes = append(notes, "running-process checks are only available on Linux; restart PHP workers after upgrading")
		}
		if procs.denied > 0 {
			notes = append(notes, fmt.Sprintf("%d processes could not be inspected (permission denied); run as root to check every running PHP worker", procs.denied))
		}
	}
	cands := discover(opt.Paths, procs)
	if len(cands) == 0 {
		notes = append(notes, "no PHP installations found; point --path at a PHP binary or its directory")
	}
	results := make([]report.Result, 0, len(cands))
	for _, c := range cands {
		results = append(results, inspect(ctx, a, c, opt))
	}
	return results, notes
}

type discovery struct {
	seen map[string]*candidate
	list []*candidate
}

func discover(extra []string, procs procInfo) []*candidate {
	d := &discovery{seen: map[string]*candidate{}}
	for _, p := range extra {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			d.addDir(p)
		} else {
			d.add(p)
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		d.addDir(dir)
	}
	for _, g := range searchGlobs() {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if nameRe.MatchString(filepath.Base(m)) {
				d.add(m)
			}
		}
	}
	for _, p := range procs.paths() {
		if _, err := os.Stat(p); err == nil {
			d.add(p)
		} else if d.seen[p] == nil {
			c := &candidate{path: p, gone: true}
			d.seen[p] = c
			d.list = append(d.list, c)
		}
	}
	for _, c := range d.list {
		c.proc = procs.running[c.path]
	}
	return d.list
}

func (d *discovery) addDir(dir string) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && nameRe.MatchString(e.Name()) {
			d.add(filepath.Join(dir, e.Name()))
		}
	}
}

func (d *discovery) add(p string) {
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		real = p
	}
	if abs, err := filepath.Abs(real); err == nil {
		real = abs
	}
	alias := ""
	if abs, err := filepath.Abs(p); err == nil && abs != real {
		alias = abs
	}
	c := d.seen[real]
	if c == nil {
		c = &candidate{path: real}
		d.seen[real] = c
		d.list = append(d.list, c)
	}
	if alias != "" && !slices.Contains(c.aliases, alias) {
		c.aliases = append(c.aliases, alias)
	}
}

func inspect(ctx context.Context, a *advisory.Advisory, c *candidate, opt Options) report.Result {
	res := report.Result{Kind: "binary", Target: c.path, SAPI: sapiOf(c.path), Aliases: c.aliases}
	if c.proc != nil {
		res.RunningPIDs = c.proc.pids
		res.StalePIDs = c.proc.stale
	}

	if c.gone {
		ver, err := "", ErrNoBuildString
		if c.proc != nil && c.proc.staleExe != "" {
			ver, err = ScanBinary(c.proc.staleExe)
		}
		if err != nil {
			res.Verdict = assess.UnknownVerdict("processes run a binary that no longer exists on disk, and its version could not be read")
		} else {
			res.Verdict = assess.Classify(a, ver)
			res.Source = "build string of the running process"
		}
		res.Notes = append(res.Notes, fmt.Sprintf("binary was deleted from disk but is still running (PID %s); restart these processes", pidList(res.RunningPIDs)))
		return res
	}

	ver, src, err := detectVersion(ctx, c.path, opt)
	if err != nil {
		res.Verdict = assess.UnknownVerdict("could not determine the PHP version: " + err.Error())
		res.Error = err.Error()
	} else {
		res.Verdict = assess.Classify(a, ver)
		res.Source = src
	}

	if !opt.NoPackages {
		applyPackage(ctx, a, &res, c.path)
	}
	if c.proc != nil && len(c.proc.stale) > 0 {
		applyStale(a, &res, c.proc)
	}
	if !opt.NoExec && res.Status.ExitCode() != 0 && (res.SAPI == "cli" || res.SAPI == "php-fpm") {
		res.Notes = append(res.Notes, iniHints(ctx, c.path, res.PHPVersion)...)
	}
	return res
}

// detectVersion reads the version from the binary's build string, falling
// back to running `<binary> -n -v`.
func detectVersion(ctx context.Context, path string, opt Options) (version, source string, err error) {
	if v, err := ScanBinary(path); err == nil {
		return v, "build string", nil
	}
	if strings.EqualFold(filepath.Ext(path), ".exe") {
		// Windows builds keep the engine in php8ts.dll / php8.dll next to php.exe.
		dlls, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "php[0-9]*.dll"))
		for _, dll := range dlls {
			if v, err := ScanBinary(dll); err == nil {
				return v, "build string in " + filepath.Base(dll), nil
			}
		}
	}
	if opt.NoExec || strings.HasSuffix(strings.ToLower(path), ".so") {
		return "", "", errors.New("no PHP build string in the file")
	}
	out, err := runCmd(ctx, path, "-n", "-v")
	if m := execVersionRe.FindSubmatch(out); m != nil {
		return string(m[1]), "`-v` output", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("running %s -v: %w", filepath.Base(path), err)
	}
	return "", "", errors.New("no PHP version in `-v` output")
}

func applyPackage(ctx context.Context, a *advisory.Advisory, res *report.Result, path string) {
	pkg := packageFor(ctx, path, a.CVEIDs())
	if pkg == nil {
		return
	}
	res.Package = pkg
	switch {
	case len(pkg.ChangelogCVEs) == len(a.CVEs) && (res.Status == assess.Vulnerable || res.Status == assess.EOL):
		res.Status = assess.VendorPatched
		res.Confidence = assess.Medium
		res.Reason = fmt.Sprintf("upstream PHP %s is affected, but the changelog of package %s %s lists %s, so the vendor backported the fix",
			res.PHPVersion, pkg.Name, pkg.Version, strings.Join(pkg.ChangelogCVEs, " and "))
		res.Remediation = ""
	case len(pkg.ChangelogCVEs) > 0 && len(pkg.ChangelogCVEs) < len(a.CVEs):
		res.Notes = append(res.Notes, fmt.Sprintf("package changelog mentions only %s", strings.Join(pkg.ChangelogCVEs, ", ")))
	}
}

func applyStale(a *advisory.Advisory, res *report.Result, p *procEntry) {
	desc := fmt.Sprintf("%d running %s (PID %s) still use a previous build that was replaced on disk",
		len(p.stale), plural(len(p.stale), "process", "processes"), pidList(p.stale))
	var running assess.Verdict
	if p.staleExe != "" {
		if v, err := ScanBinary(p.staleExe); err == nil {
			running = assess.Classify(a, v)
			desc += " (PHP " + v + ")"
		}
	}
	if res.Status.ExitCode() == 0 && running.Status.ExitCode() != 0 {
		res.Status = assess.RestartRequired
		res.Confidence = assess.High
		if running.Status == "" {
			res.Confidence = assess.Medium
		}
		res.Reason = "the binary on disk is fixed, but " + desc
		res.Remediation = fmt.Sprintf("Restart the %s service so every worker loads the patched binary.", res.SAPI)
		return
	}
	res.Notes = append(res.Notes, desc+"; restart them after upgrading")
}

// iniHints reports whether the advisory's interim mitigations are applied.
func iniHints(ctx context.Context, path, version string) []string {
	out, err := runCmd(ctx, path, "-i")
	if err != nil {
		return nil
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(strings.TrimSpace(line), " => ")
		if len(parts) >= 2 {
			if _, ok := vals[parts[0]]; !ok {
				vals[parts[0]] = parts[1]
			}
		}
	}
	var hints []string
	if isOn(vals["session.upload_progress.enabled"]) {
		hints = append(hints, "php.ini: session.upload_progress.enabled is On, a confirmed trigger path for CVE-2026-109619; turning it Off reduces exposure but is not a fix")
	}
	if v, err := phpver.Parse(version); err == nil && v.Major == 8 && v.Minor == 5 && isOn(vals["fatal_error_backtraces"]) {
		hints = append(hints, "php.ini: fatal_error_backtraces is On; the advisory's interim mitigation for PHP 8.5 sets it Off")
	}
	return hints
}

func isOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "1", "true", "yes":
		return true
	}
	return false
}

func sapiOf(path string) string {
	b := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(b, "fpm"):
		return "php-fpm"
	case strings.Contains(b, "cgi"):
		return "php-cgi"
	case strings.HasPrefix(b, "libphp"), strings.HasPrefix(b, "mod_php"):
		return "apache mod_php"
	case strings.HasPrefix(b, "lsphp"):
		return "litespeed"
	case strings.HasPrefix(b, "frankenphp"):
		return "frankenphp"
	}
	return "cli"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func pidList(pids []int) string {
	s := make([]string, 0, min(len(pids), 5))
	for _, p := range pids[:min(len(pids), 5)] {
		s = append(s, strconv.Itoa(p))
	}
	if len(pids) > 5 {
		s = append(s, "…")
	}
	return strings.Join(s, ", ")
}

// searchGlobs lists well-known install locations: distro packages, SCL and
// Remi builds, cPanel/Plesk/CloudLinux/aaPanel, LiteSpeed, Homebrew, MAMP,
// and the usual Windows stacks.
func searchGlobs() []string {
	if runtime.GOOS == "windows" {
		var g []string
		for _, root := range []string{os.Getenv("SystemDrive") + `\`, os.Getenv("ProgramFiles") + `\`} {
			if root == `\` {
				continue
			}
			g = append(g,
				root+`php*\php*.exe`, root+`PHP\*\php*.exe`, root+`PHP\php*.exe`, root+`tools\php*\php*.exe`,
				root+`xampp\php\php*.exe`, root+`laragon\bin\php\*\php*.exe`,
				root+`wamp64\bin\php\*\php*.exe`, root+`wamp\bin\php\*\php*.exe`,
			)
		}
		if home := os.Getenv("USERPROFILE"); home != "" {
			g = append(g, home+`\scoop\apps\php*\current\php*.exe`)
		}
		return g
	}
	return []string{
		"/usr/bin/php*", "/usr/sbin/php*", "/usr/local/bin/php*", "/usr/local/sbin/php*",
		"/usr/bin/lsphp*", "/usr/bin/frankenphp", "/usr/local/bin/frankenphp",
		"/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php-fpm*",
		"/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm",
		"/opt/rh/rh-php*/root/usr/bin/php*", "/opt/rh/rh-php*/root/usr/sbin/php-fpm",
		"/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
		"/opt/alt/php*/usr/bin/php*", "/opt/alt/php*/usr/sbin/php-fpm",
		"/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm",
		"/www/server/php/*/bin/php*", "/www/server/php/*/sbin/php-fpm",
		"/usr/local/lsws/lsphp*/bin/lsphp", "/usr/local/lsws/lsphp*/bin/php",
		"/usr/lib/apache2/modules/libphp*.so", "/usr/lib/apache2/mod_php*.so",
		"/usr/lib64/httpd/modules/libphp*.so", "/usr/lib/httpd/modules/libphp*.so",
		"/usr/local/apache2/modules/libphp*.so", "/usr/local/libexec/apache24/libphp*.so",
		"/opt/homebrew/opt/php*/bin/php", "/opt/homebrew/opt/php*/sbin/php-fpm",
		"/opt/homebrew/opt/php*/lib/httpd/modules/libphp.so",
		"/usr/local/opt/php*/bin/php", "/usr/local/opt/php*/sbin/php-fpm",
		"/Applications/MAMP/bin/php/php*/bin/php",
	}
}
