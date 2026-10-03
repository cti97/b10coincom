"""Report per-task-section Markdown fence parity for a plan file.

A section with an odd fence count inverts parity for every section after it, which
makes the task-brief extractor treat later headings as being inside a code block:
their briefs come out empty, or bleed into the next task. Exits non-zero if any
section is unbalanced.
"""
import re
import sys


def main() -> int:
    path = sys.argv[1]
    lines = open(path, encoding="utf-8").read().split("\n")
    cur, counts = "(preamble)", {}
    for line in lines:
        m = re.match(r"^#+\s+Task\s+\d+", line)
        if m:
            cur = line.strip()
        if line.startswith("```"):
            counts[cur] = counts.get(cur, 0) + 1
    bad = [k for k, v in counts.items() if v % 2]
    print(f"  fences: {sum(counts.values())} total, {len(counts)} sections")
    for k, v in counts.items():
        if v % 2:
            print(f"  UNBALANCED ({v} fences): {k}")
    print("  parity: FAIL" if bad else "  parity: OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
