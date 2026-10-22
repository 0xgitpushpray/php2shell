package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbedded(t *testing.T) {
	a, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(a.CVEIDs(), ","); got != "CVE-2026-109618,CVE-2026-109619" {
		t.Errorf("CVEIDs = %s", got)
	}
	if got := strings.Join(a.FixedReleases(), ","); got != "8.2.35,8.3.36,8.4.27,8.5.12" {
		t.Errorf("FixedReleases = %s", got)
	}
	if b, ok := a.Lookup(8, 1); !ok || !b.EOL || !b.SourceBackport {
		t.Errorf("8.1 should be EOL with a source backport: %+v", b)
	}
	if a.Newest().Branch != "8.5" {
		t.Errorf("Newest = %s", a.Newest().Branch)
	}
}

func TestParseRejectsBadData(t *testing.T) {
	good, _ := os.ReadFile("advisory.json")
	bad := map[string]string{
		"schema":       strings.Replace(string(good), `"schema": 1`, `"schema": 2`, 1),
		"fixed branch": strings.Replace(string(good), `"fixed": "8.3.36"`, `"fixed": "8.4.36"`, 1),
		"date":         strings.Replace(string(good), `"revision": "2026-10-22"`, `"revision": "soon"`, 1),
		"json":         "{",
	}
	for name, data := range bad {
		if _, err := Parse([]byte(data), name); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func withRevision(t *testing.T, rev string) []byte {
	t.Helper()
	a, _ := Embedded()
	return []byte(strings.Replace(string(embedded), `"revision": "`+a.Revision+`"`, `"revision": "`+rev+`"`, 1))
}

func TestLoadPrefersNewerCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PHP2SHELL_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "advisory.json"), withRevision(t, "2099-01-01"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Load("")
	if err != nil || a.Revision != "2099-01-01" {
		t.Fatalf("Load = %v, %v; want the newer cached revision", a, err)
	}
	// An older cache is ignored.
	os.WriteFile(filepath.Join(dir, "advisory.json"), withRevision(t, "2000-01-01"), 0o644)
	if a, _ := Load(""); a.Source != "embedded" {
		t.Errorf("older cache should be ignored, got %s", a.Source)
	}
}

func TestUpdate(t *testing.T) {
	t.Setenv("PHP2SHELL_CONFIG_DIR", t.TempDir())
	body := withRevision(t, "2099-01-01")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	defer srv.Close()

	a, changed, err := Update(context.Background(), srv.Client(), srv.URL)
	if err != nil || !changed || a.Revision != "2099-01-01" {
		t.Fatalf("Update = %v, %v, %v", a, changed, err)
	}
	if a, _ := Load(""); a.Revision != "2099-01-01" {
		t.Errorf("cached revision not used after update: %s", a.Revision)
	}
	if _, changed, _ := Update(context.Background(), srv.Client(), srv.URL); changed {
		t.Error("second update of the same revision should not change anything")
	}
}
