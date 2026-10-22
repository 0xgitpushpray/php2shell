package local

import (
	"slices"
	"sort"
)

// procEntry records the processes running one PHP binary or library.
type procEntry struct {
	pids     []int
	stale    []int  // processes still running a build that was deleted or replaced on disk
	staleExe string // /proc/<pid>/exe of a stale process; readable for its build string
}

// procInfo is the result of a process scan.
type procInfo struct {
	supported bool
	running   map[string]*procEntry // keyed by binary path
	denied    int                   // processes that could not be inspected
}

func (p *procInfo) add(path string, pid int, deleted bool, exeLink string) {
	if p.running == nil {
		p.running = map[string]*procEntry{}
	}
	e := p.running[path]
	if e == nil {
		e = &procEntry{}
		p.running[path] = e
	}
	if !slices.Contains(e.pids, pid) {
		e.pids = append(e.pids, pid)
	}
	if deleted && !slices.Contains(e.stale, pid) {
		e.stale = append(e.stale, pid)
		if e.staleExe == "" {
			e.staleExe = exeLink
		}
	}
}

func (p procInfo) paths() []string {
	out := make([]string, 0, len(p.running))
	for k := range p.running {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
