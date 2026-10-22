// Command php2shell checks websites and servers for PHP2Shell
// (CVE-2026-109618, CVE-2026-109619) and hunts for signs of compromise.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
	"github.com/0xgitpushpray/php2shell/internal/hunt"
	"github.com/0xgitpushpray/php2shell/internal/local"
	"github.com/0xgitpushpray/php2shell/internal/mcp"
	"github.com/0xgitpushpray/php2shell/internal/remote"
	"github.com/0xgitpushpray/php2shell/internal/report"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = ""

const (
	exitUsage = 2
	usageText = `php2shell — check websites and servers for PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Usage:
  php2shell check [flags] URL...     check websites by the PHP version in their headers
  php2shell local [flags]            inventory every PHP install on this machine
  php2shell hunt [flags] [DIR...]    look for signs of compromise in web roots and the system
  php2shell classify VERSION...      classify PHP version strings ("-" reads stdin)
  php2shell advisory                 show the advisory data in use
  php2shell update                   download the latest advisory data
  php2shell mcp                      run as an MCP server for AI agents (stdio)
  php2shell version                  print the version

  php2shell URL...                   shorthand for "php2shell check URL..."

Exit codes: 0 patched · 1 vulnerable, end-of-life, restart required or findings · 2 usage error · 3 unknown

Run "php2shell <command> -h" for command flags.
`
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func toolVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "check":
		return cmdCheck(ctx, rest, stdin, stdout, stderr)
	case "local":
		return cmdLocal(ctx, rest, stdout, stderr)
	case "hunt":
		return cmdHunt(ctx, rest, stdout, stderr)
	case "classify":
		return cmdClassify(rest, stdin, stdout, stderr)
	case "advisory":
		return cmdAdvisory(rest, stdout, stderr)
	case "update":
		return cmdUpdate(ctx, rest, stdout, stderr)
	case "mcp":
		return cmdMCP(ctx, rest, stdin, stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "php2shell", toolVersion())
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	}
	// Bare targets (and flags before them) mean "check".
	return cmdCheck(ctx, args, stdin, stdout, stderr)
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parse parses flags that may be interleaved with positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: php2shell %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// output holds the flags shared by every reporting command.
type output struct {
	format   string
	json     bool
	file     string
	noColor  bool
	quiet    bool
	advisory string
}

func (o *output) register(fs *flag.FlagSet) {
	fs.StringVar(&o.format, "format", "text", "output format: "+strings.Join(report.Formats, ", "))
	fs.BoolVar(&o.json, "json", false, "shorthand for --format json")
	fs.StringVar(&o.file, "output", "", "write the report to `FILE` instead of stdout")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colors (also honors NO_COLOR)")
	fs.BoolVar(&o.quiet, "quiet", false, "text output: only show results that need attention")
	fs.StringVar(&o.advisory, "advisory", "", "use advisory data from `FILE` instead of the built-in data")
}

func (o *output) validate() error {
	if o.json {
		o.format = "json"
	}
	if !slices.Contains(report.Formats, o.format) {
		return fmt.Errorf("unknown --format %q (use %s)", o.format, strings.Join(report.Formats, ", "))
	}
	return nil
}

func (o *output) newReport(a *advisory.Advisory, command string) *report.Report {
	return &report.Report{
		Tool:      "php2shell",
		Version:   toolVersion(),
		Command:   command,
		Generated: time.Now().UTC().Truncate(time.Second),
		Advisory:  report.AdvisoryInfo{Name: a.Name, Revision: a.Revision, CVEs: a.CVEIDs(), Source: a.Source},
	}
}

func (o *output) emit(r *report.Report, stdout, stderr io.Writer) int {
	r.Finalize()
	w := stdout
	if o.file != "" {
		f, err := os.Create(o.file)
		if err != nil {
			fmt.Fprintln(stderr, "php2shell:", err)
			return exitUsage
		}
		defer f.Close()
		w = f
	}
	color := o.file == "" && !o.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
	if err := report.Write(w, r, o.format, report.Options{Color: color, Quiet: o.quiet}); err != nil {
		fmt.Fprintln(stderr, "php2shell:", err)
		return exitUsage
	}
	return r.ExitCode
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	// Legacy Windows consoles do not render ANSI escapes; Windows Terminal does.
	return runtime.GOOS != "windows" || os.Getenv("WT_SESSION") != "" || os.Getenv("TERM") != ""
}

func usageError(stderr io.Writer, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(stderr, "php2shell:", err)
	return exitUsage
}

func loadAdvisory(path string, stderr io.Writer) (*advisory.Advisory, bool) {
	a, err := advisory.Load(path)
	if err != nil {
		fmt.Fprintln(stderr, "php2shell: loading advisory data:", err)
		return nil, false
	}
	return a, true
}

// readLines reads non-empty, non-comment lines.
func readLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func cmdCheck(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("check", "check [flags] URL...", stderr)
	var out output
	out.register(fs)
	var opt remote.Options
	var paths stringList
	var targetsFile string
	fs.DurationVar(&opt.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.BoolVar(&opt.Follow, "follow", false, "follow up to 5 redirects")
	fs.BoolVar(&opt.Deep, "deep", false, "also probe /index.php and retry HEAD requests as GET")
	fs.Var(&paths, "path", "extra `PATH` to probe on every target (repeatable)")
	fs.BoolVar(&opt.Insecure, "insecure", false, "skip TLS certificate verification")
	fs.IntVar(&opt.Concurrency, "concurrency", 8, "number of targets checked in parallel")
	fs.StringVar(&opt.UserAgent, "user-agent", "php2shell/"+toolVersion()+" (+https://github.com/0xgitpushpray/php2shell)", "User-Agent header")
	fs.StringVar(&targetsFile, "targets", "", "read targets from `FILE`, one per line (\"-\" for stdin)")
	targets, err := parse(fs, args)
	if err != nil {
		return usageError(stderr, err)
	}
	if err := out.validate(); err != nil {
		return usageError(stderr, err)
	}
	if opt.Timeout <= 0 || opt.Timeout > time.Minute {
		return usageError(stderr, errors.New("--timeout must be between 0 and 1m"))
	}
	opt.Paths = paths
	if targetsFile != "" {
		r := stdin
		if targetsFile != "-" {
			f, err := os.Open(targetsFile)
			if err != nil {
				return usageError(stderr, err)
			}
			defer f.Close()
			r = f
		}
		lines, err := readLines(r)
		if err != nil {
			return usageError(stderr, err)
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 {
		fs.Usage()
		return exitUsage
	}
	a, ok := loadAdvisory(out.advisory, stderr)
	if !ok {
		return exitUsage
	}
	rep := out.newReport(a, "check")
	rep.Results = remote.New(a, opt).CheckAll(ctx, targets)
	return out.emit(rep, stdout, stderr)
}

func cmdLocal(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("local", "local [flags]", stderr)
	var out output
	out.register(fs)
	var opt local.Options
	var paths stringList
	fs.Var(&paths, "path", "also inspect the PHP binary or directory at `PATH` (repeatable)")
	fs.BoolVar(&opt.NoExec, "no-exec", false, "never execute PHP binaries (version from build strings only)")
	fs.BoolVar(&opt.NoPackages, "no-packages", false, "skip OS package and changelog checks")
	fs.BoolVar(&opt.NoProcesses, "no-processes", false, "skip running-process checks")
	pos, err := parse(fs, args)
	if err != nil {
		return usageError(stderr, err)
	}
	if err := out.validate(); err != nil {
		return usageError(stderr, err)
	}
	opt.Paths = append(paths, pos...)
	a, ok := loadAdvisory(out.advisory, stderr)
	if !ok {
		return exitUsage
	}
	rep := out.newReport(a, "local")
	rep.Results, rep.Notes = local.Run(ctx, a, opt)
	code := out.emit(rep, stdout, stderr)
	if len(rep.Results) == 0 && code == 0 {
		return 3 // nothing found is not the same as patched
	}
	return code
}

func cmdHunt(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("hunt", "hunt [flags] [DIR...]", stderr)
	var out output
	out.register(fs)
	var since string
	var maxMB int64
	var noSystem bool
	fs.StringVar(&since, "since", "", "flag files changed on or after `DATE` (YYYY-MM-DD; default: first observed exploitation)")
	fs.Int64Var(&maxMB, "max-size", 2, "skip content scanning of files larger than this many MB")
	fs.BoolVar(&noSystem, "no-system", false, "skip cron, account and temp-directory checks")
	roots, err := parse(fs, args)
	if err != nil {
		return usageError(stderr, err)
	}
	if err := out.validate(); err != nil {
		return usageError(stderr, err)
	}
	a, ok := loadAdvisory(out.advisory, stderr)
	if !ok {
		return exitUsage
	}
	if since == "" {
		since = a.ExploitedSince
	}
	sinceT, err := time.ParseInLocation("2006-01-02", since, time.Local)
	if err != nil {
		return usageError(stderr, fmt.Errorf("invalid --since %q (use YYYY-MM-DD)", since))
	}
	if len(roots) == 0 {
		roots = hunt.DefaultRoots()
	}
	rep := out.newReport(a, "hunt")
	findings, notes, err := hunt.Run(ctx, hunt.Options{Roots: roots, Since: sinceT, MaxFileSize: maxMB << 20, System: !noSystem})
	if err != nil {
		return usageError(stderr, err)
	}
	rep.Findings, rep.Notes = findings, notes
	if len(roots) == 0 {
		rep.Notes = append(rep.Notes, "no web roots found; pass the directories to scan as arguments")
	}
	return out.emit(rep, stdout, stderr)
}

func cmdClassify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("classify", "classify [flags] VERSION... (\"-\" reads stdin)", stderr)
	var out output
	out.register(fs)
	versions, err := parse(fs, args)
	if err != nil {
		return usageError(stderr, err)
	}
	if err := out.validate(); err != nil {
		return usageError(stderr, err)
	}
	if i := slices.Index(versions, "-"); i >= 0 {
		lines, err := readLines(stdin)
		if err != nil {
			return usageError(stderr, err)
		}
		versions = slices.Concat(versions[:i], lines, versions[i+1:])
	}
	if len(versions) == 0 {
		fs.Usage()
		return exitUsage
	}
	a, ok := loadAdvisory(out.advisory, stderr)
	if !ok {
		return exitUsage
	}
	rep := out.newReport(a, "classify")
	for _, v := range versions {
		rep.Results = append(rep.Results, report.Result{Kind: "version", Target: v, Verdict: assess.Classify(a, v)})
	}
	return out.emit(rep, stdout, stderr)
}

func cmdAdvisory(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("advisory", "advisory [flags]", stderr)
	var file string
	var asJSON bool
	fs.StringVar(&file, "advisory", "", "use advisory data from `FILE`")
	fs.BoolVar(&asJSON, "json", false, "print the raw advisory JSON")
	if _, err := parse(fs, args); err != nil {
		return usageError(stderr, err)
	}
	a, ok := loadAdvisory(file, stderr)
	if !ok {
		return exitUsage
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(a); err != nil {
			return usageError(stderr, err)
		}
		return 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s advisory · revision %s · source: %s\n", a.Name, a.Revision, a.Source)
	fmt.Fprintf(&b, "Disclosed %s · exploited in the wild since %s\n\n", a.Disclosed, a.ExploitedSince)
	for _, c := range a.CVEs {
		fmt.Fprintf(&b, "  %s  CVSS 4.0 %.1f  %s\n", c.ID, c.CVSS4, c.Title)
	}
	b.WriteString("\nBranch  Status\n")
	for _, br := range a.Branches {
		status := "fixed in " + br.Fixed
		if br.EOL {
			status = "end-of-life, no official fix"
			if br.SourceBackport {
				status += " (source backport available)"
			}
		}
		fmt.Fprintf(&b, "  %-5s %s\n", br.Branch, status)
	}
	b.WriteString("\nMitigations\n")
	for _, m := range a.Mitigations {
		fmt.Fprintf(&b, "  • %s\n", m)
	}
	b.WriteString("\nReferences\n")
	for _, r := range a.References {
		fmt.Fprintf(&b, "  %s\n    %s\n", r.Title, r.URL)
	}
	io.WriteString(stdout, b.String())
	return 0
}

func cmdUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("update", "update [flags]", stderr)
	var url string
	var timeout time.Duration
	fs.StringVar(&url, "url", advisory.DefaultUpdateURL, "download advisory data from `URL`")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "download timeout")
	if _, err := parse(fs, args); err != nil {
		return usageError(stderr, err)
	}
	a, changed, err := advisory.Update(ctx, &http.Client{Timeout: timeout}, url)
	if err != nil {
		fmt.Fprintln(stderr, "php2shell: update failed:", err)
		return 1
	}
	if changed {
		fmt.Fprintf(stdout, "Updated advisory data to revision %s (saved to %s)\n", a.Revision, a.Source)
	} else {
		fmt.Fprintf(stdout, "Advisory data is up to date (revision %s, %s)\n", a.Revision, a.Source)
	}
	return 0
}

func cmdMCP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("mcp", "mcp [flags]", stderr)
	var file string
	var timeout time.Duration
	fs.StringVar(&file, "advisory", "", "use advisory data from `FILE`")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "per-request timeout for check_url")
	if _, err := parse(fs, args); err != nil {
		return usageError(stderr, err)
	}
	a, ok := loadAdvisory(file, stderr)
	if !ok {
		return exitUsage
	}
	s := &mcp.Server{
		Advisory: a,
		Version:  toolVersion(),
		Remote:   remote.Options{Timeout: timeout, UserAgent: "php2shell/" + toolVersion() + " (+https://github.com/0xgitpushpray/php2shell)"},
	}
	if err := s.Serve(ctx, stdin, stdout); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "php2shell mcp:", err)
		return 1
	}
	return 0
}
