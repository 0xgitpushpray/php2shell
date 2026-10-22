// Package remote checks websites for PHP2Shell by reading the PHP version
// they expose in HTTP response headers. It sends ordinary HEAD/GET requests
// and never sends exploit payloads.
package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/0xgitpushpray/php2shell/internal/advisory"
	"github.com/0xgitpushpray/php2shell/internal/assess"
	"github.com/0xgitpushpray/php2shell/internal/report"
)

// Options configure remote checks.
type Options struct {
	Timeout     time.Duration // per request
	Follow      bool          // follow up to 5 redirects
	Deep        bool          // also probe /index.php and retry HEAD as GET
	Paths       []string      // extra paths to probe, resolved against each target
	Insecure    bool          // skip TLS certificate verification
	Concurrency int
	UserAgent   string
}

var versionRe = regexp.MustCompile(`(?i)\bPHP[/ ](\d+\.\d+\.\d+[^\s,;()]*)`)

// Scanner probes URLs. It is safe for concurrent use.
type Scanner struct {
	adv    *advisory.Advisory
	opt    Options
	client *http.Client
}

// New returns a Scanner.
func New(a *advisory.Advisory, opt Options) *Scanner {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 8
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if opt.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   opt.Timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if !opt.Follow || len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Scanner{adv: a, opt: opt, client: client}
}

// NormalizeTarget validates a target and adds https:// when no scheme is given.
func NormalizeTarget(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty target")
	}
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, fmt.Errorf("target %q contains whitespace or control characters", raw)
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", raw)
	}
	if u.User != nil {
		return nil, errors.New("credentials in URLs are not supported")
	}
	u.Fragment = ""
	return u, nil
}

// CheckAll probes every target and returns results in input order.
func (s *Scanner) CheckAll(ctx context.Context, targets []string) []report.Result {
	results := make([]report.Result, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(s.opt.Concurrency, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = s.Check(ctx, targets[i])
			}
		}()
	}
	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// Check probes one target.
func (s *Scanner) Check(ctx context.Context, target string) report.Result {
	res := report.Result{Kind: "url", Target: target}
	u, err := NormalizeTarget(target)
	if err != nil {
		res.Verdict = assess.UnknownVerdict(err.Error())
		res.Error = err.Error()
		return res
	}
	res.Target = u.String()

	urls := []string{u.String()}
	paths := s.opt.Paths
	if s.opt.Deep {
		paths = append([]string{"/index.php"}, paths...)
	}
	for _, p := range paths {
		if ref, err := url.Parse(p); err == nil {
			if v := u.ResolveReference(ref).String(); !slices.Contains(urls, v) {
				urls = append(urls, v)
			}
		}
	}

	var signals []string
	var lastErr error
	reached := false
	for _, probe := range urls {
		methods := []string{http.MethodHead}
		if s.opt.Deep {
			methods = append(methods, http.MethodGet)
		}
		for _, method := range methods {
			h, final, err := s.fetch(ctx, method, probe)
			if err != nil {
				lastErr = err
				break
			}
			reached = true
			if ver, header := findVersion(h); ver != "" {
				res.Verdict = assess.Classify(s.adv, ver)
				res.PHPDetected = true
				res.Source = header + " header"
				if final != res.Target {
					res.Source += " of " + final
				}
				res.Notes = append(res.Notes, "header versions can be altered by proxies or hidden; confirm with `php2shell local` on the server")
				return res
			}
			signals = appendUnique(signals, phpSignals(h)...)
		}
	}

	switch {
	case len(signals) > 0:
		res.PHPDetected = true
		res.Verdict = assess.UnknownVerdict(fmt.Sprintf("PHP detected (%s) but the version is hidden", strings.Join(signals, ", ")))
		res.Remediation = "Run `php2shell local` on the server to check the PHP build directly."
	case !reached && lastErr != nil:
		res.Error = lastErr.Error()
		res.Verdict = assess.UnknownVerdict("request failed: " + lastErr.Error())
	default:
		res.Verdict = assess.UnknownVerdict("no PHP version in the X-Powered-By or Server headers; UNKNOWN does not mean patched")
		res.Remediation = "Try --deep, or run `php2shell local` on the server."
	}
	return res
}

// fetch sends one request and returns the response headers and final URL.
// A HEAD answered with 405 or 501 is retried as GET. Bodies are never read.
func (s *Scanner) fetch(ctx context.Context, method, target string) (http.Header, string, error) {
	resp, err := s.do(ctx, method, target)
	if err != nil {
		return nil, "", err
	}
	if method == http.MethodHead && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		resp.Body.Close()
		if resp, err = s.do(ctx, http.MethodGet, target); err != nil {
			return nil, "", err
		}
	}
	resp.Body.Close()
	return resp.Header, resp.Request.URL.String(), nil
}

func (s *Scanner) do(ctx context.Context, method, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	if s.opt.UserAgent != "" {
		req.Header.Set("User-Agent", s.opt.UserAgent)
	}
	return s.client.Do(req)
}

// findVersion returns the PHP version exposed in X-Powered-By or Server.
func findVersion(h http.Header) (version, header string) {
	for _, name := range []string{"X-Powered-By", "Server"} {
		for _, v := range h.Values(name) {
			if m := versionRe.FindStringSubmatch(v); m != nil {
				return m[1], name
			}
		}
	}
	return "", ""
}

// phpSignals returns hints that the site runs PHP without exposing a version.
func phpSignals(h http.Header) []string {
	var out []string
	for _, v := range h.Values("X-Powered-By") {
		if strings.Contains(strings.ToLower(v), "php") {
			out = append(out, "X-Powered-By: "+v)
		}
	}
	for _, c := range h.Values("Set-Cookie") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(c)), "PHPSESSID=") {
			out = append(out, "PHPSESSID cookie")
			break
		}
	}
	return out
}

func appendUnique(list []string, items ...string) []string {
	for _, it := range items {
		if !slices.Contains(list, it) {
			list = append(list, it)
		}
	}
	return list
}
