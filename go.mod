// go.mod declares this directory as a Go module named "sentri".
// Milestone 1 has ZERO external dependencies on purpose — everything we need
// (clone flags, sethostname, mount, exec) lives in the Go standard library's
// "syscall" package. We only add third-party libs later if a milestone truly
// needs one (e.g. golang.org/x/sys/unix for the syscall-name lookup table in
// Milestone 4).
//
// The "go 1.21" line is the minimum Go language/toolchain version. Any Go
// >= 1.21 on the EC2 box will build this.
module sentri

go 1.21
