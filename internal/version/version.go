// Package version holds the b10coin build version and the identity of the
// build that is actually running.
//
// The two are different facts and the audit's S-10 is what happens when only
// the first exists. Version names the RELEASE: it is a compile-time constant,
// it is the same in every binary cut from this tree, and it cannot say WHICH
// binary is running. Two nodes built from commits on either side of a
// consensus change therefore print the same banner, the same chain ID and the
// same height — the documented picture of a healthy committee — and fork at
// the first block where their rules differ.
//
// The build identity is therefore READ, never declared: Build takes it from
// the Go toolchain's own stamp (debug.ReadBuildInfo's vcs.revision and
// vcs.modified settings), so the compiler is the single source of truth and
// there is nothing here for a human to forget to bump. A hand-maintained
// Commit constant would be a second source of truth that drifts silently,
// which is the defect rather than the cure.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the semantic version of the node software.
const Version = "0.1.0"

// shortRev is how many characters of the revision an Identity shows. Twelve
// hex digits is 48 bits — no two commits of this repository collide — and it
// keeps the startup banner a single readable line. `b10coin version` and the
// banner deliberately print the SAME token, because an operator comparing
// three Pis must not have to decide whether two different renderings name the
// same build.
const shortRev = 12

// Identity is what a running binary can truthfully say about the build it came
// from.
//
// An empty Revision is not an error to hide. A build can legitimately carry no
// VCS information: `-buildvcs=false`, or a build from a source tarball with no
// .git directory, produce one. Saying so is the only honest option, and it is
// deliberately NOT the same output as a clean build — the failure mode S-10
// describes is a field that prints nothing and reads like agreement.
type Identity struct {
	// Version is the semantic version of the software. It is never empty.
	Version string
	// Revision is the VCS revision the build was made from, or "" when the
	// build carries no VCS stamp at all.
	Revision string
	// Modified reports whether the work tree had uncommitted changes when the
	// binary was built. It is meaningful only when ModifiedKnown is true.
	Modified bool
	// ModifiedKnown reports whether the build recorded the modification state.
	// A build that stamps a revision but not this setting exists in no Go
	// release we know of; if one ever appears, the third state says "not
	// recorded" instead of guessing "clean".
	ModifiedKnown bool
}

// Build reports the identity of the running binary.
//
// It reads the stamp the toolchain embedded at link time. When the build was
// made with `-buildvcs=false` (or outside any VCS) there is no stamp and the
// result carries an empty Revision, which String renders as an explicit
// "unknown" rather than as blank output.
func Build() Identity {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		// No build information at all (e.g. a binary from before module
		// support, or an unusual toolchain). Degrading is correct here: the
		// node must still start and must still print something true.
		return Identity{Version: Version}
	}
	return fromSettings(info.Settings)
}

// fromSettings is the seam the tests drive. It is split out of Build because
// the three states — stamped clean, stamped modified, and unstamped — are a
// property of the settings list, and a test must be able to produce the
// unstamped one without needing a binary built three different ways.
func fromSettings(settings []debug.BuildSetting) Identity {
	id := Identity{Version: Version}
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			id.Revision = strings.TrimSpace(s.Value)
		case "vcs.modified":
			id.Modified = strings.TrimSpace(s.Value) == "true"
			id.ModifiedKnown = true
		}
	}
	return id
}

// String renders the identity as the one token `b10coin version` prints and
// the node startup banner carries:
//
//	0.1.0 rev ded04c891698 (clean)                     built from a clean checkout
//	0.1.0 rev ded04c891698 (modified)                  built with uncommitted changes
//	0.1.0 rev ded04c891698 (modification state not recorded)
//	0.1.0 rev unknown (built without VCS information)   no stamp at all
//
// The unstamped form is a complete sentence on purpose: an operator reading
// three of these must be able to tell "same build" from "nobody can tell".
func (i Identity) String() string {
	v := i.Version
	if v == "" {
		v = Version // a zero Identity still names the software
	}
	if i.Revision == "" {
		return v + " rev unknown (built without VCS information)"
	}
	rev := i.Revision
	if len(rev) > shortRev {
		rev = rev[:shortRev]
	}
	switch {
	case !i.ModifiedKnown:
		return v + " rev " + rev + " (modification state not recorded)"
	case i.Modified:
		return v + " rev " + rev + " (modified)"
	default:
		return v + " rev " + rev + " (clean)"
	}
}
