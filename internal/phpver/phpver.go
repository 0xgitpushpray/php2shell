// Package phpver parses and compares PHP version strings such as "8.3.12",
// "8.5.0RC2" or vendor builds like "8.1.2-1ubuntu2.14".
package phpver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed PHP version. Suffix holds anything after the patch
// number: a pre-release tag ("RC1", "-dev") or a vendor build ("-1ubuntu2.14").
type Version struct {
	Major, Minor, Patch int
	Suffix              string
}

var (
	versionRe    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(.*)$`)
	prereleaseRe = regexp.MustCompile(`(?i)^[-._~]?(dev|alpha|beta|rc)`)
)

// Parse parses a PHP version string. A leading "PHP/" or "PHP " is accepted.
func Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	for _, p := range []string{"PHP/", "PHP ", "php/", "php "} {
		s = strings.TrimPrefix(s, p)
	}
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("invalid PHP version %q", s)
	}
	var v Version
	var err error
	for i, dst := range []*int{&v.Major, &v.Minor, &v.Patch} {
		if *dst, err = strconv.Atoi(m[i+1]); err != nil {
			return Version{}, fmt.Errorf("invalid PHP version %q: %w", s, err)
		}
	}
	v.Suffix = m[4]
	return v, nil
}

// String returns the version in its original form, suffix included.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.Suffix)
}

// Branch returns the release branch, e.g. "8.3".
func (v Version) Branch() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Prerelease reports whether v is a dev, alpha, beta or RC build.
func (v Version) Prerelease() bool {
	return prereleaseRe.MatchString(v.Suffix)
}

// VendorBuild reports whether v carries a distribution or vendor build
// suffix. Such builds may contain backported fixes that the upstream
// version number does not reflect.
func (v Version) VendorBuild() bool {
	return v.Suffix != "" && !v.Prerelease()
}

// Compare compares the numeric parts of a and b and returns -1, 0 or +1.
// Suffixes are ignored.
func Compare(a, b Version) int {
	for _, d := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		switch {
		case d[0] < d[1]:
			return -1
		case d[0] > d[1]:
			return 1
		}
	}
	return 0
}
