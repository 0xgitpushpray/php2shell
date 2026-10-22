package local

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// ErrNoBuildString means a file does not contain a PHP build string.
var ErrNoBuildString = errors.New("no PHP build string found")

// Every PHP SAPI (CLI, FPM, CGI, mod_php, LiteSpeed, FrankenPHP) compiles in
// the constant "X-Powered-By: PHP/" PHP_VERSION, so the exact version can be
// read from the file without executing it.
var marker = []byte("X-Powered-By: PHP/")

const maxVersionLen = 64

// ScanBinary reads the PHP version compiled into an executable or shared
// library. It streams the file, so large static builds are fine.
func ScanBinary(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return scanReader(f)
}

func scanReader(r io.Reader) (string, error) {
	const chunk = 1 << 20
	tail := len(marker) + maxVersionLen
	buf := make([]byte, 0, chunk+tail)
	tmp := make([]byte, chunk)
	for {
		n, err := io.ReadFull(r, tmp)
		buf = append(buf, tmp[:n]...)
		eof := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if err != nil && !eof {
			return "", err
		}
		for {
			i := bytes.Index(buf, marker)
			if i < 0 {
				break
			}
			rest := buf[i+len(marker):]
			if len(rest) < maxVersionLen && !eof {
				break // the version may continue in the next chunk
			}
			v := rest[:min(len(rest), maxVersionLen)]
			if j := bytes.IndexFunc(v, func(r rune) bool { return !isVersionRune(r) }); j >= 0 {
				v = v[:j]
			}
			if len(v) > 0 && v[0] >= '0' && v[0] <= '9' {
				return string(v), nil
			}
			buf = rest // not a version; keep searching after this hit
		}
		if eof {
			return "", ErrNoBuildString
		}
		if len(buf) > tail {
			buf = append(buf[:0], buf[len(buf)-tail:]...)
		}
	}
}

func isVersionRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
		r == '.' || r == '-' || r == '+' || r == '~' || r == '_'
}
