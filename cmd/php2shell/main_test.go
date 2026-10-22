package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestClassifyExitCodes(t *testing.T) {
	tests := map[string]int{"8.3.12": 1, "8.4.27": 0, "7.4.33": 1, "8.6.0": 3}
	for v, want := range tests {
		if code, out, _ := runCLI(t, "", "classify", v); code != want {
			t.Errorf("classify %s: exit %d, want %d\n%s", v, code, want, out)
		}
	}
}

func TestClassifyStdinJSON(t *testing.T) {
	code, out, _ := runCLI(t, "8.5.12\n# comment\n8.2.1\n", "classify", "-", "--json")
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	var rep struct {
		Results []struct {
			Target, Status string
		}
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(rep.Results) != 2 || rep.Results[0].Status != "patched" || rep.Results[1].Status != "vulnerable" || rep.ExitCode != 1 {
		t.Errorf("results = %+v", rep)
	}
}

func TestCheckCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
	}))
	defer srv.Close()
	code, out, _ := runCLI(t, "", "check", srv.URL, "--format", "csv")
	if code != 1 || !strings.Contains(out, ",vulnerable,") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// A bare URL is shorthand for "check".
	if code, _, _ := runCLI(t, "", srv.URL); code != 1 {
		t.Errorf("shorthand exit %d", code)
	}
	// Targets from stdin.
	if code, out, _ := runCLI(t, srv.URL+"\n", "check", "--targets", "-", "--quiet"); code != 1 || !strings.Contains(out, "VULNERABLE") {
		t.Errorf("--targets - exit %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"check"},
		{"classify"},
		{"classify", "8.3.1", "--format", "xml"},
		{"check", "--timeout", "5m", "example.com"},
		{"check", "--bogus"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, "", args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, "", "check", "-h"); code != 0 {
		t.Errorf("-h should exit 0, got %d", code)
	}
}

func TestAdvisoryCommand(t *testing.T) {
	code, out, _ := runCLI(t, "", "advisory")
	if code != 0 || !strings.Contains(out, "CVE-2026-109618") || !strings.Contains(out, "fixed in 8.3.36") {
		t.Errorf("exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "", "advisory", "--json")
	var v map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || v["name"] != "PHP2Shell" {
		t.Errorf("advisory --json: exit %d\n%s", code, out)
	}
}

func TestVersionCommand(t *testing.T) {
	if code, out, _ := runCLI(t, "", "version"); code != 0 || !strings.HasPrefix(out, "php2shell ") {
		t.Errorf("exit %d %q", code, out)
	}
}
