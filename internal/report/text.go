package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/0xgitpushpray/php2shell/internal/assess"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

type painter bool

func (p painter) paint(code, s string) string {
	if !p {
		return s
	}
	return code + s + ansiReset
}

func statusColor(s assess.Status) string {
	switch s.ExitCode() {
	case 0:
		return ansiGreen
	case 3:
		return ansiYellow
	}
	return ansiRed
}

func severityColor(s string) string {
	switch s {
	case High:
		return ansiRed
	case Medium:
		return ansiYellow
	}
	return ansiDim
}

func writeText(w io.Writer, r *Report, opt Options) error {
	p := painter(opt.Color)
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s · %s advisory %s · %s\n\n",
		p.paint(ansiBold, r.Tool), r.Version, r.Advisory.Name, r.Advisory.Revision, strings.Join(r.Advisory.CVEs, ", "))

	shown := 0
	for _, res := range r.Results {
		if opt.Quiet && res.Status.ExitCode() == 0 {
			continue
		}
		shown++
		label := fmt.Sprintf("%-16s", strings.ToUpper(string(res.Status)))
		fmt.Fprintf(&b, "%s %s\n", p.paint(ansiBold+statusColor(res.Status), label), res.Target)

		var facts []string
		if res.PHPVersion != "" {
			facts = append(facts, "PHP "+res.PHPVersion)
		}
		if res.FixedIn != "" && res.Status != assess.Patched {
			facts = append(facts, "fixed in "+res.FixedIn)
		}
		if res.SAPI != "" {
			facts = append(facts, res.SAPI)
		}
		if res.Source != "" {
			facts = append(facts, "via "+res.Source)
		}
		if res.Package != nil {
			pkg := res.Package.Name
			if res.Package.Version != "" {
				pkg += " " + res.Package.Version
			}
			facts = append(facts, res.Package.Manager+": "+pkg)
		}
		facts = append(facts, string(res.Confidence)+" confidence")
		fmt.Fprintf(&b, "  %s\n", p.paint(ansiDim, strings.Join(facts, " · ")))
		fmt.Fprintf(&b, "  %s\n", res.Reason)
		if res.Remediation != "" && res.Status.ExitCode() != 0 {
			fmt.Fprintf(&b, "  → %s\n", res.Remediation)
		}
		for _, n := range res.Notes {
			fmt.Fprintf(&b, "  • %s\n", n)
		}
		b.WriteString("\n")
	}
	if opt.Quiet && shown == 0 && len(r.Results) > 0 {
		fmt.Fprintf(&b, "All %d targets are patched.\n\n", len(r.Results))
	}

	for _, f := range r.Findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		label := fmt.Sprintf("%-7s", strings.ToUpper(f.Severity))
		fmt.Fprintf(&b, "%s %s  %s\n", p.paint(ansiBold+severityColor(f.Severity), label), p.paint(ansiBold, f.Rule), loc)
		fmt.Fprintf(&b, "        %s", f.Detail)
		if !f.Modified.IsZero() {
			fmt.Fprintf(&b, " %s", p.paint(ansiDim, "(modified "+f.Modified.Format("2006-01-02 15:04")+")"))
		}
		b.WriteString("\n")
		if f.Snippet != "" {
			fmt.Fprintf(&b, "        %s\n", p.paint(ansiDim, f.Snippet))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n")
	}

	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n")
	}

	b.WriteString(summaryLine(r))
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func summaryLine(r *Report) string {
	order := []string{
		string(assess.Vulnerable), string(assess.EOL), string(assess.RestartRequired),
		string(assess.Unknown), string(assess.VendorPatched), string(assess.Patched),
		High, Medium, Low,
	}
	var parts []string
	for _, k := range order {
		if n := r.Summary[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(parts) == 0 {
		return "Summary: nothing found"
	}
	return "Summary: " + strings.Join(parts, " · ")
}
