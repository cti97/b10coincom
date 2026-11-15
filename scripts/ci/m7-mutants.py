#!/usr/bin/env python3
"""M7 mutant check.

Every mutant below is COMPILE-CONFIRMED: the script builds the whole module
before running the test, so a mutant that fails to compile is reported as a
BROKEN MUTANT (which proves nothing) rather than as a caught one. Each mutant
is then expected to be killed by the named test; a survivor fails the script.

Usage: python3 scripts/ci/m7-mutants.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, ".superpowers", "sdd", "audit-2026-10-04")
ENV = dict(
    os.environ,
    GOCACHE=os.path.join(CACHE, ".gocache"),
    GOMODCACHE=os.path.join(CACHE, ".gomodcache"),
    GOPATH=os.path.join(CACHE, ".gopath"),
    GOTOOLCHAIN="go1.27.4",
    GOMAXPROCS="2",
)

# (label, file, [(old, new), ...], package, test regex)
MUTANTS = [
    (
        "rounds.log made prunable (the table's sharp edge)",
        "internal/retention/retention.go",
        [("{RoundLog, false,", "{RoundLog, true,")],
        "./internal/retention/",
        "TestTheTableForbidsPruningEverySafetyCriticalRecord",
    ),
    (
        "checkpoint state-root check removed",
        "internal/chain/chain_prune.go",
        [(
            """	if root := r.State.Root(); root != r.Head.Header.StateRoot {
		return fmt.Errorf("%w: the checkpoint's state hashes to %x, but its block commits %x: the state snapshot is not the state that block committed", ErrCheckpointMismatch, root[:8], r.Head.Header.StateRoot[:8])
	}""",
            "",
        )],
        "./internal/chain/",
        "TestOpenResumeRefusesAMismatchedCheckpoint",
    ),
    (
        "Append ignores the checkpoint base",
        "internal/store/store.go",
        [(
            """	want := s.first
	if s.have {
		want = s.last + 1
	}""",
            """	want := uint64(1)
	if s.have {
		want = s.last + 1
	}""",
        )],
        "./internal/consensus/",
        "TestAWipedNodeRecoversFromACheckpointToTheSameHeadAndRoot",
    ),
    (
        "scan ignores the horizon offset",
        "internal/store/store.go",
        [(
            """	start := int64(SegmentHeaderLen)
	if !s.have && s.firstOffset > start {
		start = s.firstOffset
	}""",
            "	start := int64(SegmentHeaderLen)",
        )],
        "./internal/store/",
        "TestAPartialPruneSkipsTheBoundaryPrefix",
    ),
    (
        "prune allowed off an epoch boundary",
        "internal/chain/chain_prune.go",
        [("	if (upTo+1)%blocks != 0 {", "	if false {")],
        "./internal/chain/",
        "TestPruneHistoryOnlyAtAnEpochBoundary",
    ),
    (
        "pruner's horizon lands ON an epoch boundary instead of before one",
        "internal/consensus/prune.go",
        [("	horizon := k*blocks - 1", "	horizon := k * blocks")],
        "./internal/consensus/",
        "TestAWipedNodeRecoversFromACheckpointToTheSameHeadAndRoot",
    ),
]


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, env=ENV, capture_output=True, text=True)


def main():
    backup = tempfile.mkdtemp(prefix="m7-mutants-")
    failures = 0
    try:
        for label, path, edits, pkg, regex in MUTANTS:
            full = os.path.join(ROOT, path)
            saved = os.path.join(backup, path.replace("/", "_"))
            shutil.copyfile(full, saved)
            try:
                src = open(full, encoding="utf-8").read()
                for old, new in edits:
                    if old not in src:
                        print(f"MUTANT {label}: PATCH DID NOT APPLY (source moved); not counted")
                        failures += 1
                        break
                    src = src.replace(old, new, 1)
                else:
                    open(full, "w", encoding="utf-8").write(src)
                    build = run(["go", "build", "./..."])
                    if build.returncode != 0:
                        print(f"MUTANT {label}: BROKEN (does not compile) - not a caught mutant")
                        print(build.stderr.strip().splitlines()[-1:])
                        failures += 1
                    else:
                        test = run(["go", "test", "-count=1", "-run", regex, pkg])
                        if test.returncode == 0:
                            print(f"MUTANT {label}: SURVIVED ({pkg} -run {regex})")
                            failures += 1
                        else:
                            print(f"MUTANT {label}: caught (compiles; {pkg} -run {regex} fails)")
            finally:
                shutil.copyfile(saved, full)
    finally:
        shutil.rmtree(backup, ignore_errors=True)
    if failures:
        print(f"MUTANT CHECK: FAILED ({failures})")
        return 1
    print("MUTANT CHECK: all mutants compile and are caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
