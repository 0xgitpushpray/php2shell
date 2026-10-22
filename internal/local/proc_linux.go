//go:build linux

package local

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var webServerRe = regexp.MustCompile(`^(apache2|httpd|httpd-prefork|httpd-worker|httpd-event|litespeed|lshttpd)$`)

// scanProcesses finds running PHP workers and web servers with mod_php loaded,
// and flags those whose binary was deleted or replaced on disk: after a
// package upgrade they keep running the old, vulnerable code until restarted.
func scanProcesses() procInfo {
	info := procInfo{supported: true, running: map[string]*procEntry{}}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		info.supported = false
		return info
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		exe, err := os.Readlink(exeLink)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				info.denied++
			}
			continue
		}
		path, deleted := strings.CutSuffix(exe, " (deleted)")
		switch base := filepath.Base(path); {
		case nameRe.MatchString(base):
			info.add(path, pid, deleted, exeLink)
		case webServerRe.MatchString(base):
			info.addMappedLibs(pid)
		}
	}
	return info
}

// addMappedLibs records PHP shared libraries (mod_php) loaded by a process.
func (info *procInfo) addMappedLibs(pid int) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			info.denied++
		}
		return
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		path, deleted := strings.CutSuffix(line[i:], " (deleted)")
		if seen[path] || !nameRe.MatchString(filepath.Base(path)) {
			continue
		}
		seen[path] = true
		info.add(path, pid, deleted, "")
	}
}
