// Package advisory holds the PHP2Shell vulnerability data: CVEs, affected
// release branches, fixed releases, mitigations and references.
//
// The data ships embedded in the binary and can be refreshed at runtime with
// Update, which caches a newer revision in the user's config directory.
package advisory

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/phpver"
)

// DefaultUpdateURL is where Update fetches fresh advisory data.
const DefaultUpdateURL = "https://raw.githubusercontent.com/0xgitpushpray/php2shell/main/internal/advisory/advisory.json"

//go:embed advisory.json
var embedded []byte

// CVE describes one vulnerability covered by the advisory.
type CVE struct {
	ID    string  `json:"id"`
	GHSA  string  `json:"ghsa"`
	Title string  `json:"title"`
	CVSS4 float64 `json:"cvss4"`
	URL   string  `json:"url"`
}

// Branch is the fix status of one PHP release branch, e.g. "8.3".
type Branch struct {
	Branch         string `json:"branch"`
	Fixed          string `json:"fixed,omitempty"`
	EOL            bool   `json:"eol,omitempty"`
	SourceBackport bool   `json:"source_backport,omitempty"`
	Note           string `json:"note,omitempty"`

	major, minor int
	fixed        phpver.Version
}

// FixedVersion returns the first release of the branch that contains the fix.
// It is the zero Version for end-of-life branches.
func (b Branch) FixedVersion() phpver.Version { return b.fixed }

// Reference is a link to an advisory or write-up.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Advisory is the full data set.
type Advisory struct {
	Schema         int         `json:"schema"`
	Name           string      `json:"name"`
	Revision       string      `json:"revision"`
	Disclosed      string      `json:"disclosed"`
	ExploitedSince string      `json:"exploited_since"`
	FirstAffected  string      `json:"first_affected"`
	CVEs           []CVE       `json:"cves"`
	Branches       []Branch    `json:"branches"`
	Mitigations    []string    `json:"mitigations"`
	References     []Reference `json:"references"`

	// Source records where the data was loaded from: "embedded" or a path.
	Source string `json:"-"`
}

var branchRe = regexp.MustCompile(`^(\d+)\.(\d+)$`)

const dateLayout = "2006-01-02"

// Parse decodes and validates advisory data. source is recorded for messages.
func Parse(data []byte, source string) (*Advisory, error) {
	var a Advisory
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("advisory %s: %w", source, err)
	}
	if a.Schema != 1 {
		return nil, fmt.Errorf("advisory %s: unsupported schema %d", source, a.Schema)
	}
	for _, d := range []string{a.Revision, a.Disclosed, a.ExploitedSince} {
		if _, err := time.Parse(dateLayout, d); err != nil {
			return nil, fmt.Errorf("advisory %s: invalid date %q", source, d)
		}
	}
	if _, err := phpver.Parse(a.FirstAffected); err != nil {
		return nil, fmt.Errorf("advisory %s: first_affected: %w", source, err)
	}
	if len(a.CVEs) == 0 || len(a.Branches) == 0 {
		return nil, fmt.Errorf("advisory %s: no CVEs or branches", source)
	}
	for i := range a.Branches {
		b := &a.Branches[i]
		m := branchRe.FindStringSubmatch(b.Branch)
		if m == nil {
			return nil, fmt.Errorf("advisory %s: invalid branch %q", source, b.Branch)
		}
		b.major, _ = strconv.Atoi(m[1])
		b.minor, _ = strconv.Atoi(m[2])
		if b.EOL {
			continue
		}
		v, err := phpver.Parse(b.Fixed)
		if err != nil || v.Major != b.major || v.Minor != b.minor || v.Suffix != "" {
			return nil, fmt.Errorf("advisory %s: branch %s has invalid fixed release %q", source, b.Branch, b.Fixed)
		}
		b.fixed = v
	}
	a.Source = source
	return &a, nil
}

// Embedded returns the advisory data compiled into the binary.
func Embedded() (*Advisory, error) { return Parse(embedded, "embedded") }

// CachePath is where Update stores downloaded advisory data. The directory
// can be overridden with the PHP2SHELL_CONFIG_DIR environment variable.
func CachePath() (string, error) {
	dir := os.Getenv("PHP2SHELL_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "php2shell")
	}
	return filepath.Join(dir, "advisory.json"), nil
}

// Load returns the advisory data to use. An override path always wins;
// otherwise a cached download is used when it is newer than the embedded data.
func Load(override string) (*Advisory, error) {
	if override != "" {
		data, err := os.ReadFile(override)
		if err != nil {
			return nil, err
		}
		return Parse(data, override)
	}
	base, err := Embedded()
	if err != nil {
		return nil, err
	}
	if p, err := CachePath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			if cached, err := Parse(data, p); err == nil && cached.Revision > base.Revision {
				return cached, nil
			}
		}
	}
	return base, nil
}

// Update downloads advisory data from url and caches it if it is newer than
// the data Load returns. It returns the advisory now in effect.
func Update(ctx context.Context, client *http.Client, url string) (a *Advisory, changed bool, err error) {
	current, err := Load("")
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("fetch %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false, err
	}
	fresh, err := Parse(data, url)
	if err != nil {
		return nil, false, err
	}
	if fresh.Revision <= current.Revision {
		return current, false, nil
	}
	p, err := CachePath()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, false, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return nil, false, err
	}
	if err := os.Rename(tmp, p); err != nil {
		return nil, false, err
	}
	fresh.Source = p
	return fresh, true, nil
}

// Lookup returns the branch entry for major.minor.
func (a *Advisory) Lookup(major, minor int) (Branch, bool) {
	for _, b := range a.Branches {
		if b.major == major && b.minor == minor {
			return b, true
		}
	}
	return Branch{}, false
}

// Newest returns the highest branch listed in the advisory.
func (a *Advisory) Newest() Branch {
	best := a.Branches[0]
	for _, b := range a.Branches[1:] {
		if b.major > best.major || (b.major == best.major && b.minor > best.minor) {
			best = b
		}
	}
	return best
}

// FixedReleases lists the fixed release of every supported branch, oldest first.
func (a *Advisory) FixedReleases() []string {
	var out []phpver.Version
	for _, b := range a.Branches {
		if !b.EOL {
			out = append(out, b.fixed)
		}
	}
	slices.SortFunc(out, phpver.Compare)
	s := make([]string, len(out))
	for i, v := range out {
		s[i] = v.String()
	}
	return s
}

// CVEIDs returns the CVE identifiers covered by the advisory.
func (a *Advisory) CVEIDs() []string {
	ids := make([]string, len(a.CVEs))
	for i, c := range a.CVEs {
		ids[i] = c.ID
	}
	return ids
}
