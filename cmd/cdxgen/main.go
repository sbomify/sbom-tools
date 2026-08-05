// Command cdxgen runs the cdxgen pinned in our bun.lock.
//
// cdxgen is one of our tools, so it is pinned where every other one is -- in
// a lockfile, verified by the package manager that owns it. bun.lock records
// a sha512 integrity hash for it and 197 other packages, and `bun install
// --frozen-lockfile` refuses anything that does not match. Shipping upstream's
// prebuilt binary instead would mean maintaining a second, parallel pin: a
// sha256 of our own, of a different artefact, in a file no bot can read.
//
// What is left is an entry-point problem. The package's own launcher is
// node_modules/.bin/cdxgen, a JavaScript file beginning "#!/usr/bin/env node",
// and a distroless image has neither env nor node -- execve cannot resolve the
// interpreter and reports ENOENT on the script, which reads confusingly as
// "cdxgen: No such file or directory" for a file that is plainly there.
//
// So this: a static binary that puts cdxgen on PATH under its own name and
// hands off to the bundled bun. No shell, no shebang, nothing to resolve.
//
// bun rather than Node, and not interchangeably: for axios cdxgen reports 9
// components under bun and 39 under Node. The 9 are the production closure
// axios actually declares; the extra thirty are Node builtins and
// devDependencies returned despite --required-only.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func main() {
	// Locate the bundle from our own path rather than an environment
	// variable: the bundle is relocatable and the caller should not have to
	// tell us where it was unpacked.
	self, err := os.Executable()
	if err != nil {
		fail("cannot determine own path: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	prefix := filepath.Dir(filepath.Dir(self)) // <prefix>/bin/cdxgen -> <prefix>

	bun := filepath.Join(prefix, "bin", "bun")
	entry := filepath.Join(prefix, "node_modules", "@cyclonedx", "cdxgen", "bin", "cdxgen.js")
	for _, required := range []string{bun, entry} {
		if _, err := os.Stat(required); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fail("%s is missing; the bundle is incomplete", required)
			}
			fail("cannot read %s: %v", required, err)
		}
	}

	// Exec rather than spawn: cdxgen's exit code and signals are the caller's
	// to see, and an extra process in between only obscures them.
	argv := append([]string{bun, entry}, os.Args[1:]...)
	if err := syscall.Exec(bun, argv, os.Environ()); err != nil {
		fail("cannot run %s: %v", bun, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cdxgen: "+format+"\n", args...)
	os.Exit(1)
}
