// Package hunt looks for signs that a PHP server was compromised: web
// shells, PHP code hidden in uploads or images, recently changed PHP files,
// and suspicious cron jobs, accounts and binaries dropped in temp
// directories. It only reads files and never modifies or deletes anything.
package hunt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/report"
)

// Options configure a hunt.
type Options struct {
	Roots       []string  // web roots to scan
	Since       time.Time // flag files changed on or after this time
	MaxFileSize int64     // larger files are not content-scanned
	System      bool      // also check cron, accounts and temp directories (Unix)
}

type rule struct {
	id, severity, detail string
	re                   *regexp.Regexp
}

// contentRules match lines of PHP files. They are heuristics: review each
// finding, since some frameworks legitimately use similar constructs.
var contentRules = []rule{
	{"eval-decoded-payload", report.High, "evaluates a decoded or decompressed payload",
		regexp.MustCompile(`(?i)\b(eval|assert)\s*\(\s*@?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\s*\(`)},
	{"exec-request-input", report.High, "executes code or commands taken directly from request input",
		regexp.MustCompile(`(?i)\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`)},
	{"dynamic-call-request-input", report.High, "calls a function whose name comes from request input",
		regexp.MustCompile(`(?i)@?\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(`)},
	{"create-function-request-input", report.High, "builds a function from request input",
		regexp.MustCompile(`(?i)\bcreate_function\s*\(.*\$_(GET|POST|REQUEST|COOKIE)`)},
	{"known-webshell", report.High, "contains a marker of a well-known web shell",
		regexp.MustCompile(`(?i)(c99shell|r57shell|b374k|wso\s*shell|FilesMan|IndoXploit|AlfaTeam|Alfa\s*Shell|p0wny|weevely|china\s*chopper|ANTSWORD)`)},
	{"preg-replace-eval", report.Medium, "uses the removed preg_replace /e modifier, a classic code-execution trick",
		regexp.MustCompile(`(?i)\bpreg_replace\s*\(\s*['"]/[^'"]*/[a-df-z]*e[a-z]*['"]\s*,`)},
	{"hex-obfuscation", report.Medium, "contains long hex-escaped strings, common in obfuscated malware",
		regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){12,}`)},
	{"encoded-blob", report.Medium, "contains a very long base64-like blob",
		regexp.MustCompile(`[A-Za-z0-9+/]{1000,}={0,2}`)}, // RE2 caps repeat counts at 1000
}

var (
	phpExts   = map[string]bool{".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true, ".pht": true, ".phar": true, ".inc": true}
	imageExts = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true, ".bmp": true, ".webp": true, ".svg": true}
	skipDirs  = map[string]bool{".git": true, ".svn": true, ".hg": true, "node_modules": true}
	uploadDir = regexp.MustCompile(`(?i)(^|[/\\])(uploads?|images?|img|media|files)([/\\])`)
	phpOpen   = []byte("<?php")
)

type hunter struct {
	opt      Options
	findings []report.Finding
	notes    []string
	scanned  int
}

// Run performs the hunt.
func Run(ctx context.Context, opt Options) ([]report.Finding, []string, error) {
	if opt.MaxFileSize <= 0 {
		opt.MaxFileSize = 2 << 20
	}
	h := &hunter{opt: opt}
	for _, root := range opt.Roots {
		if err := h.walk(ctx, root); err != nil {
			return nil, nil, err
		}
	}
	if opt.System {
		if runtime.GOOS == "windows" {
			h.notes = append(h.notes, "system checks (cron, accounts, temp directories) are Unix-only and were skipped")
		} else {
			h.system()
		}
	}
	h.notes = append([]string{fmt.Sprintf("scanned %d files in %d web roots for changes since %s", h.scanned, len(opt.Roots), opt.Since.Format("2006-01-02"))}, h.notes...)

	rank := map[string]int{report.High: 0, report.Medium: 1, report.Low: 2}
	sort.SliceStable(h.findings, func(i, j int) bool {
		a, b := h.findings[i], h.findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return a.Path < b.Path
	})
	return h.findings, h.notes, nil
}

// DefaultRoots returns common web roots that exist on this machine.
func DefaultRoots() []string {
	var globs []string
	if runtime.GOOS == "windows" {
		d := os.Getenv("SystemDrive") + `\`
		globs = []string{d + `inetpub\wwwroot`, d + `xampp\htdocs`, d + `laragon\www`, d + `wamp64\www`, d + `wamp\www`}
	} else {
		globs = []string{"/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/home/*/public_html",
			"/home/*/domains/*/public_html", "/var/www/vhosts/*/httpdocs", "/www/wwwroot", "/usr/local/lsws/Example/html"}
	}
	var roots []string
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.IsDir() {
				roots = append(roots, m)
			}
		}
	}
	return roots
}

func (h *hunter) add(f report.Finding) { h.findings = append(h.findings, f) }

func (h *hunter) walk(ctx context.Context, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			if path == root {
				return fmt.Errorf("hunt %s: %w", root, err)
			}
			return nil // unreadable subtree; keep going
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !phpExts[ext] && !imageExts[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		h.scanned++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		h.checkFile(path, string(filepath.Separator)+rel, ext, info)
		return nil
	})
}

// checkFile inspects one file. rel is its path relative to the web root,
// used for directory heuristics so the root's own location does not matter.
func (h *hunter) checkFile(path, rel, ext string, info fs.FileInfo) {
	recent := !info.ModTime().Before(h.opt.Since)
	mod := info.ModTime()

	var data []byte
	if info.Size() <= h.opt.MaxFileSize {
		data, _ = os.ReadFile(path)
	}

	if imageExts[ext] {
		if bytes.Contains(data, phpOpen) {
			h.add(report.Finding{Severity: report.High, Rule: "php-in-image", Path: path, Modified: mod,
				Detail: "image file contains PHP code"})
		}
		return
	}

	if uploadDir.MatchString(rel) && ext != ".inc" && !isPlaceholder(data) {
		h.add(report.Finding{Severity: report.Medium, Rule: "php-in-upload-dir", Path: path, Modified: mod,
			Detail: "PHP file inside an upload/media directory"})
	}
	if strings.HasPrefix(filepath.Base(path), ".") {
		h.add(report.Finding{Severity: report.Medium, Rule: "hidden-php-file", Path: path, Modified: mod,
			Detail: "hidden PHP file"})
	}
	if recent {
		h.add(report.Finding{Severity: report.Low, Rule: "recently-modified", Path: path, Modified: mod,
			Detail: "PHP file changed since " + h.opt.Since.Format("2006-01-02") + "; confirm it was a legitimate deploy"})
	}
	if data == nil {
		return
	}
	hit := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), int(h.opt.MaxFileSize)+1)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		for _, r := range contentRules {
			if hit[r.id] {
				continue
			}
			if loc := r.re.FindStringIndex(text); loc != nil {
				hit[r.id] = true
				h.add(report.Finding{Severity: r.severity, Rule: r.id, Path: path, Line: line, Modified: mod,
					Detail: r.detail, Snippet: snippet(text, loc[0])})
			}
		}
	}
}

// isPlaceholder recognizes the tiny "Silence is golden" index.php files that
// WordPress and others drop into upload directories.
func isPlaceholder(data []byte) bool {
	return len(data) < 200 && bytes.Contains(bytes.ToLower(data), []byte("silence is golden"))
}

func snippet(line string, at int) string {
	start := max(0, at-40)
	end := min(len(line), at+120)
	s := strings.TrimSpace(line[start:end])
	if start > 0 {
		s = "…" + s
	}
	if end < len(line) {
		s += "…"
	}
	return s
}

var suspiciousCron = regexp.MustCompile(`(?i)((curl|wget)[^|;\n]*\|\s*(ba|z|da)?sh|base64\s+(-d|--decode)|/dev/tcp/|\bnc(at)?\s+(-e|-c)|python[0-9.]*\s+-c|\bperl\s+-e|/dev/shm/|/tmp/\.)`)

// system checks cron, accounts and temp directories (Unix only).
func (h *hunter) system() {
	var cronFiles []string
	for _, g := range []string{"/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"} {
		m, _ := filepath.Glob(g)
		cronFiles = append(cronFiles, m...)
	}
	for _, f := range cronFiles {
		info, err := os.Stat(f)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if !info.ModTime().Before(h.opt.Since) {
			h.add(report.Finding{Severity: report.Medium, Rule: "cron-modified", Path: f, Modified: info.ModTime(),
				Detail: "cron file changed since " + h.opt.Since.Format("2006-01-02")})
		}
		data, err := os.ReadFile(f)
		if err != nil {
			if os.IsPermission(err) {
				h.notes = append(h.notes, "cannot read "+f+" (permission denied); run as root for complete system checks")
			}
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
				if loc := suspiciousCron.FindStringIndex(t); loc != nil {
					h.add(report.Finding{Severity: report.High, Rule: "cron-suspicious", Path: f, Line: i + 1, Modified: info.ModTime(),
						Detail: "cron job downloads, decodes or runs code from a temp location", Snippet: snippet(t, loc[0])})
				}
			}
		}
	}

	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for i, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 7 && f[2] == "0" && f[0] != "root" {
				h.add(report.Finding{Severity: report.High, Rule: "extra-root-account", Path: "/etc/passwd", Line: i + 1,
					Detail: fmt.Sprintf("account %q has UID 0", f[0])})
			}
		}
		if info, err := os.Stat("/etc/passwd"); err == nil && !info.ModTime().Before(h.opt.Since) {
			h.add(report.Finding{Severity: report.Medium, Rule: "accounts-modified", Path: "/etc/passwd", Modified: info.ModTime(),
				Detail: "user accounts changed since " + h.opt.Since.Format("2006-01-02") + "; check for unexpected users"})
		}
	}

	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(strings.TrimPrefix(path, dir), string(filepath.Separator)) >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() || info.ModTime().Before(h.opt.Since) {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			switch {
			case phpExts[ext]:
				h.add(report.Finding{Severity: report.Medium, Rule: "temp-php-file", Path: path, Modified: info.ModTime(),
					Detail: "PHP file in a temp directory"})
			case info.Mode().Perm()&0o111 != 0 || isELF(path):
				h.add(report.Finding{Severity: report.Medium, Rule: "temp-executable", Path: path, Modified: info.ModTime(),
					Detail: "executable dropped in a temp directory"})
			}
			return nil
		})
	}
}

func isELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	_, err = f.Read(magic[:])
	return err == nil && string(magic[:]) == "\x7fELF"
}
