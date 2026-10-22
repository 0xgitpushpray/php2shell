// Package report defines the scan result model and renders it as text,
// JSON, CSV or SARIF.
package report

import (
	"fmt"
	"io"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/assess"
)

// Result is the verdict for one target: a URL, a PHP binary or a version string.
type Result struct {
	Kind   string `json:"kind"` // "url", "binary" or "version"
	Target string `json:"target"`
	SAPI   string `json:"sapi,omitempty"`
	Source string `json:"source,omitempty"` // where the version came from
	assess.Verdict
	PHPDetected bool     `json:"php_detected,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Package     *Package `json:"package,omitempty"`
	RunningPIDs []int    `json:"running_pids,omitempty"`
	StalePIDs   []int    `json:"stale_pids,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// Package is the OS package that owns a PHP binary.
type Package struct {
	Manager       string   `json:"manager"`
	Name          string   `json:"name"`
	Version       string   `json:"version,omitempty"`
	ChangelogCVEs []string `json:"changelog_cves,omitempty"`
}

// Severity levels for hunt findings.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Finding is a possible sign of compromise found by `php2shell hunt`.
type Finding struct {
	Severity string    `json:"severity"`
	Rule     string    `json:"rule"`
	Path     string    `json:"path"`
	Line     int       `json:"line,omitempty"`
	Detail   string    `json:"detail"`
	Snippet  string    `json:"snippet,omitempty"`
	Modified time.Time `json:"modified,omitzero"`
}

// AdvisoryInfo identifies the advisory data a report was produced with.
type AdvisoryInfo struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	CVEs     []string `json:"cves"`
	Source   string   `json:"source"`
}

// Report is the output of one php2shell command.
type Report struct {
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	Command   string         `json:"command"`
	Generated time.Time      `json:"generated"`
	Advisory  AdvisoryInfo   `json:"advisory"`
	Results   []Result       `json:"results,omitempty"`
	Findings  []Finding      `json:"findings,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
	Summary   map[string]int `json:"summary"`
	ExitCode  int            `json:"exit_code"`
}

// Finalize computes the summary counts and exit code.
func (r *Report) Finalize() {
	r.Summary = map[string]int{}
	worst := 0
	for _, res := range r.Results {
		r.Summary[string(res.Status)]++
		worst = worse(worst, res.Status.ExitCode())
	}
	for _, f := range r.Findings {
		r.Summary[f.Severity]++
		if f.Severity == High || f.Severity == Medium {
			worst = worse(worst, 1)
		}
	}
	r.ExitCode = worst
}

// worse ranks exit codes: 1 (at risk) beats 3 (unknown) beats 0 (safe).
func worse(a, b int) int {
	rank := func(c int) int {
		switch c {
		case 1:
			return 2
		case 3:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "csv", "sarif"}

// Options control rendering.
type Options struct {
	Color bool // ANSI colors in text output
	Quiet bool // text output: hide patched results
}

// Write renders r in the given format.
func Write(w io.Writer, r *Report, format string, opt Options) error {
	switch format {
	case "text", "":
		return writeText(w, r, opt)
	case "json":
		return writeJSON(w, r)
	case "csv":
		return writeCSV(w, r)
	case "sarif":
		return writeSARIF(w, r)
	}
	return fmt.Errorf("unknown format %q", format)
}
