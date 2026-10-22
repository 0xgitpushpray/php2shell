//go:build !linux

package local

// scanProcesses is only implemented on Linux, where /proc exposes which
// binary each process is running.
func scanProcesses() procInfo { return procInfo{} }
