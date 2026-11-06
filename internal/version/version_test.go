package version

import (
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionIsSemver(t *testing.T) {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version %q is not semver", Version)
	}
}

// The four renderings are the whole contract of Identity.String, and the
// third and fourth exist because an EMPTY field is the failure mode audit S-10
// describes: a node that printed nothing where the build should be would read
// exactly like a node in agreement with its peers.
func TestIdentityRendersEveryStampState(t *testing.T) {
	const full = "ded04c8916989f136bb0d0d08c330102d289fa02"
	cases := []struct {
		name string
		id   Identity
		want string
	}{
		{
			name: "stamped and clean",
			id:   Identity{Version: Version, Revision: full, ModifiedKnown: true},
			want: Version + " rev ded04c891698 (clean)",
		},
		{
			name: "stamped and modified",
			id:   Identity{Version: Version, Revision: full, Modified: true, ModifiedKnown: true},
			want: Version + " rev ded04c891698 (modified)",
		},
		{
			// No Go release stamps a revision without vcs.modified, so this
			// state is defensive: it must say "not recorded", never "clean".
			name: "revision but no modification state",
			id:   Identity{Version: Version, Revision: full},
			want: Version + " rev ded04c891698 (modification state not recorded)",
		},
		{
			name: "no VCS stamp at all",
			id:   Identity{Version: Version},
			want: Version + " rev unknown (built without VCS information)",
		},
		{
			name: "zero Identity still names the software",
			id:   Identity{},
			want: Version + " rev unknown (built without VCS information)",
		},
		{
			name: "a short revision is not padded or truncated oddly",
			id:   Identity{Version: Version, Revision: "abc1234", ModifiedKnown: true},
			want: Version + " rev abc1234 (clean)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.id.String(); got != c.want {
				t.Fatalf("String() = %q, want %q", got, c.want)
			}
		})
	}
}

// fromSettings is the seam Build uses; these are the settings the toolchain
// actually emits, in the shape `go version -m` prints them. The nil case is
// the graceful degrade: a binary built with -buildvcs=false, or from a source
// tarball with no .git, carries NEITHER key, and that must produce the
// explicit "unknown" rather than an empty field.
func TestBuildIdentityFromSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		rev      string
		modified bool
		known    bool
	}{
		{name: "no VCS information", settings: nil},
		{
			name: "clean checkout",
			settings: []debug.BuildSetting{
				{Key: "GOOS", Value: "linux"},
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: "ded04c8916989f136bb0d0d08c330102d289fa02"},
				{Key: "vcs.time", Value: "2026-11-06T09:10:38Z"},
				{Key: "vcs.modified", Value: "false"},
			},
			rev:   "ded04c8916989f136bb0d0d08c330102d289fa02",
			known: true,
		},
		{
			name: "dirty checkout",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "ded04c8916989f136bb0d0d08c330102d289fa02"},
				{Key: "vcs.modified", Value: "true"},
			},
			rev:      "ded04c8916989f136bb0d0d08c330102d289fa02",
			modified: true,
			known:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fromSettings(c.settings)
			if got.Version != Version {
				t.Fatalf("Version = %q, want %q", got.Version, Version)
			}
			if got.Revision != c.rev {
				t.Fatalf("Revision = %q, want %q", got.Revision, c.rev)
			}
			if got.Modified != c.modified {
				t.Fatalf("Modified = %v, want %v", got.Modified, c.modified)
			}
			if got.ModifiedKnown != c.known {
				t.Fatalf("ModifiedKnown = %v, want %v", got.ModifiedKnown, c.known)
			}
		})
	}
}

// Build() must never produce something an operator could mistake for a
// matching build. Whatever the test binary was built with, the rendering is a
// complete sentence that either names a revision or says it has none.
func TestBuildAlwaysNamesTheSoftwareAndItsRevisionState(t *testing.T) {
	id := Build()
	got := id.String()
	if !strings.HasPrefix(got, Version+" rev ") {
		t.Fatalf("Build().String() = %q: it must always start with the version and a revision field", got)
	}
	if strings.Contains(got, "rev (") || strings.Contains(got, "rev  ") {
		t.Fatalf("Build().String() = %q: the revision field is empty", got)
	}
	if id.Revision == "" {
		if !strings.Contains(got, "rev unknown (built without VCS information)") {
			t.Fatalf("Build().String() = %q: an unstamped build must say so explicitly", got)
		}
		return
	}
	if !regexp.MustCompile(`^[0-9a-f]{7,64}$`).MatchString(id.Revision) {
		t.Fatalf("Build().Revision = %q, which is not a revision the toolchain would stamp", id.Revision)
	}
	if !strings.Contains(got, id.Revision[:min(len(id.Revision), shortRev)]) {
		t.Fatalf("Build().String() = %q does not contain its own revision %q", got, id.Revision)
	}
}
