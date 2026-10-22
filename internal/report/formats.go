package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/0xgitpushpray/php2shell/internal/assess"
)

func writeJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	if len(r.Findings) > 0 && len(r.Results) == 0 {
		cw.Write([]string{"severity", "rule", "path", "line", "detail", "modified"})
		for _, f := range r.Findings {
			mod := ""
			if !f.Modified.IsZero() {
				mod = f.Modified.UTC().Format("2006-01-02T15:04:05Z")
			}
			cw.Write([]string{f.Severity, f.Rule, f.Path, strconv.Itoa(f.Line), f.Detail, mod})
		}
	} else {
		cw.Write([]string{"kind", "target", "status", "confidence", "php_version", "fixed_in", "sapi", "source", "reason", "remediation", "error"})
		for _, res := range r.Results {
			cw.Write([]string{res.Kind, res.Target, string(res.Status), string(res.Confidence), res.PHPVersion,
				res.FixedIn, res.SAPI, res.Source, res.Reason, res.Remediation, res.Error})
		}
	}
	cw.Flush()
	return cw.Error()
}

// SARIF 2.1.0, the format GitHub code scanning and most security dashboards ingest.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

const repoURL = "https://github.com/0xgitpushpray/php2shell"

func writeSARIF(w io.Writer, r *Report) error {
	driver := sarifDriver{Name: r.Tool, Version: r.Version, InformationURI: repoURL}
	ruleSeen := map[string]bool{}
	addRule := func(id, desc string) {
		if !ruleSeen[id] {
			ruleSeen[id] = true
			driver.Rules = append(driver.Rules, sarifRule{ID: id, ShortDescription: sarifMessage{desc}, HelpURI: repoURL + "#results"})
		}
	}
	results := []sarifResult{}

	for _, res := range r.Results {
		if res.Status.ExitCode() == 0 {
			continue
		}
		id := "php2shell/" + string(res.Status)
		addRule(id, fmt.Sprintf("%s: PHP %s", r.Advisory.Name, res.Status))
		level := "error"
		if res.Status == assess.Unknown {
			level = "note"
		}
		msg := res.Reason
		if res.Remediation != "" {
			msg += ". " + res.Remediation
		}
		results = append(results, sarifResult{
			RuleID: id, Level: level, Message: sarifMessage{msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{toURI(res.Target)}}}},
		})
	}
	for _, f := range r.Findings {
		id := "hunt/" + f.Rule
		addRule(id, f.Detail)
		level := map[string]string{High: "error", Medium: "warning"}[f.Severity]
		if level == "" {
			level = "note"
		}
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{toURI(f.Path)}}
		if f.Line > 0 {
			loc.Region = &sarifRegion{StartLine: f.Line}
		}
		results = append(results, sarifResult{
			RuleID: id, Level: level, Message: sarifMessage{f.Detail},
			Locations: []sarifLocation{{PhysicalLocation: loc}},
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	})
}

// toURI turns a URL or file path into a SARIF artifact URI.
func toURI(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	p := filepath.ToSlash(target)
	if filepath.IsAbs(target) {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p // Windows drive paths: C:/x -> /C:/x
		}
		return (&url.URL{Scheme: "file", Path: p}).String()
	}
	return p
}
