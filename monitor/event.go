package monitor

// event.go defines the syscall event that flows from the tracer to its sinks,
// plus the JSON-lines sink. It is PORTABLE (no ptrace, no build tag) so the
// detector and its unit tests build on any platform.

import (
	"encoding/json"
	"io"
)

// SyscallEvent is one observed syscall. The tracer (Milestone 4) produces these;
// the JSON logger (below, feeding the Milestone 5 learner) and the live detector
// (Milestone 6) consume them.
type SyscallEvent struct {
	Time    string   `json:"ts"`             // RFC3339 nanosecond timestamp
	Syscall string   `json:"syscall"`        // resolved name, e.g. "openat"
	PID     int      `json:"pid"`            // host-visible pid of the tracee
	Args    []uint64 `json:"args"`           // raw syscall args (registers)
	Path    string   `json:"path,omitempty"` // decoded path arg, when applicable
}

// NewJSONLogger returns an emit function that writes each event as one JSON line
// to w — the trace-log format the baseline learner reads back.
func NewJSONLogger(w io.Writer) func(SyscallEvent) {
	enc := json.NewEncoder(w)
	return func(ev SyscallEvent) { _ = enc.Encode(&ev) }
}
