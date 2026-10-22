package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
)

func scanner(t *testing.T, opt Options) *Scanner {
	t.Helper()
	a, err := advisory.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	opt.Timeout = 5 * time.Second
	return New(a, opt)
}

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestHeaders(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		value   string
		status  assess.Status
		version string
	}{
		{"x-powered-by vulnerable", "X-Powered-By", "PHP/8.3.12", assess.Vulnerable, "8.3.12"},
		{"x-powered-by patched", "X-Powered-By", "PHP/8.5.12", assess.Patched, "8.5.12"},
		{"server header", "Server", "Apache/2.4.58 (Ubuntu) PHP/8.4.27 OpenSSL/3.0", assess.Patched, "8.4.27"},
		{"eol", "X-Powered-By", "PHP/7.4.33", assess.EOL, "7.4.33"},
		{"vendor build", "X-Powered-By", "PHP/8.1.2-1ubuntu2.14", assess.EOL, "8.1.2-1ubuntu2.14"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := serve(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead {
					t.Errorf("unexpected %s request", r.Method)
				}
				w.Header().Set(tt.header, tt.value)
			})
			res := scanner(t, Options{}).Check(context.Background(), url)
			if res.Status != tt.status || res.PHPVersion != tt.version || !res.PHPDetected {
				t.Fatalf("got %s %q (%s)", res.Status, res.PHPVersion, res.Reason)
			}
			if !strings.HasPrefix(res.Source, tt.header) {
				t.Errorf("source = %q", res.Source)
			}
		})
	}
}

func TestHeadNotAllowedFallsBackToGet(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.2.20")
	})
	res := scanner(t, Options{}).Check(context.Background(), url)
	if res.Status != assess.Vulnerable {
		t.Fatalf("got %s (%s)", res.Status, res.Reason)
	}
}

func TestRedirects(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/app", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.1")
	})
	if res := scanner(t, Options{}).Check(context.Background(), url); res.Status != assess.Unknown {
		t.Errorf("without --follow: got %s, want unknown", res.Status)
	}
	res := scanner(t, Options{Follow: true}).Check(context.Background(), url)
	if res.Status != assess.Vulnerable || !strings.Contains(res.Source, "/app") {
		t.Errorf("with --follow: got %s via %q", res.Status, res.Source)
	}
}

func TestHiddenVersion(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "PHPSESSID=abc; path=/")
	})
	res := scanner(t, Options{}).Check(context.Background(), url)
	if res.Status != assess.Unknown || !res.PHPDetected || !strings.Contains(res.Reason, "PHPSESSID") {
		t.Fatalf("got %s detected=%v (%s)", res.Status, res.PHPDetected, res.Reason)
	}
}

func TestDeepProbesIndexPHP(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			w.Header().Set("X-Powered-By", "PHP/8.4.1")
		}
	})
	if res := scanner(t, Options{}).Check(context.Background(), url); res.Status != assess.Unknown {
		t.Errorf("shallow: got %s", res.Status)
	}
	if res := scanner(t, Options{Deep: true}).Check(context.Background(), url); res.Status != assess.Vulnerable {
		t.Errorf("deep: got %s (%s)", res.Status, res.Reason)
	}
}

func TestUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connections are now refused
	res := scanner(t, Options{}).Check(context.Background(), url)
	if res.Status != assess.Unknown || res.Error == "" {
		t.Fatalf("got %s error=%q", res.Status, res.Error)
	}
}

func TestCheckAllKeepsOrder(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8."+strings.TrimPrefix(r.URL.Path, "/")+".0")
	})
	targets := []string{url + "/2", url + "/3", "bad target", url + "/4", url + "/5"}
	results := scanner(t, Options{Concurrency: 3}).CheckAll(context.Background(), targets)
	want := []string{"8.2.0", "8.3.0", "", "8.4.0", "8.5.0"}
	for i, r := range results {
		if r.PHPVersion != want[i] {
			t.Errorf("result %d: version %q, want %q", i, r.PHPVersion, want[i])
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	ok := map[string]string{
		"example.com":                "https://example.com",
		"http://example.com/a#frag":  "http://example.com/a",
		" https://example.com:8443 ": "https://example.com:8443",
	}
	for in, want := range ok {
		u, err := NormalizeTarget(in)
		if err != nil || u.String() != want {
			t.Errorf("NormalizeTarget(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"", "ftp://example.com", "http://user:pw@example.com", "exa mple.com", "https://"} {
		if _, err := NormalizeTarget(in); err == nil {
			t.Errorf("NormalizeTarget(%q) should fail", in)
		}
	}
}
