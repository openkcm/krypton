package main

import "golang.org/x/sys/unix"

// allowPtrace grants any process permission to ptrace-attach to this one.
// With YAMA ptrace_scope=1 (the default in recent Docker Desktop VM kernels)
// only ancestors may attach, so the analysis script's gcore would be denied
// even with dump protection disabled. Dump protection via PR_SET_DUMPABLE
// still blocks attaches independently of this exception, which is exactly
// what the dump test asserts.
func allowPtrace() {
	// Best effort: fails with EINVAL on kernels without YAMA, where no
	// exception is needed in the first place.
	_ = unix.Prctl(unix.PR_SET_PTRACER, unix.PR_SET_PTRACER_ANY, 0, 0, 0)
}
