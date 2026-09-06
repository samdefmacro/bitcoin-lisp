#!/usr/bin/env python3
"""Render the GA11 verdict and fix tables from the data directory and git history.

Usage: scripts/gap-analysis/render-ga11.py [BASE-COMMIT] [--doc FILE]

With --doc, the tables replace the text between the lines
`<!-- render-ga11:begin -->` and `<!-- render-ga11:end -->` in FILE instead
of going to stdout, so docs/gap-analysis-11.md is regenerated, never hand-edited.

Reads docs/gap-analysis-11-data/dim-*.json (survey severity) and
docs/gap-analysis-11-data/verdicts/*.json (final severity, status), then walks
`git log BASE..HEAD` for the commits whose subject or body names a finding id,
skipping the survey/verdict/ceiling commits.  Prints two Markdown tables to
stdout: the per-finding table (id, dimension, survey -> final severity, status,
fix commit subject) and the per-dimension tally.  A finding whose id appears in
no fix commit is listed as `open`.
"""
import glob
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict

DATA = "docs/gap-analysis-11-data"
DOC = sys.argv[sys.argv.index("--doc") + 1] if "--doc" in sys.argv else None
ARGS = [a for a in sys.argv[1:] if not a.startswith("--") and a != DOC]
BASE = ARGS[0] if ARGS else "f5fc0da"
BEGIN, END = "<!-- render-ga11:begin -->", "<!-- render-ga11:end -->"
ID_RE = re.compile(r"\b[0-9a-f]{8}\b")


def survey():
    out = {}
    for path in sorted(glob.glob(f"{DATA}/dim-*.json")):
        doc = json.load(open(path))
        for f in doc["findings"]:
            out[f["id"]] = (doc["dimension"], f["severity"], f["title"])
    return out


def verdicts():
    out = {}
    for path in sorted(glob.glob(f"{DATA}/verdicts/*.json")):
        d = json.load(open(path))
        out[d["id"]] = d
    return out


def fix_commits():
    """Map finding id -> list of commit subjects that name it."""
    raw = subprocess.run(
        ["git", "log", "--format=%h%x00%s%x00%b%x01", f"{BASE}..HEAD"],
        capture_output=True, text=True, check=True).stdout
    fixes = defaultdict(list)
    for rec in raw.split("\x01"):
        parts = rec.strip("\n").split("\x00")
        if len(parts) < 3:
            continue
        short, subject, body = parts[0], parts[1], parts[2]
        if subject.startswith("GA11") or "ceiling" in subject:
            continue
        for fid in set(ID_RE.findall(subject + " " + body)):
            fixes[fid].append((short, subject))
    return fixes


def aliased_fixes(fixes):
    """Fold in fixed-by.json: a finding fixed under a sibling id's commit."""
    try:
        alias = json.load(open(f"{DATA}/fixed-by.json"))
    except FileNotFoundError:
        return fixes
    log = subprocess.run(["git", "log", "--format=%h %s", f"{BASE}..HEAD"],
                         capture_output=True, text=True, check=True).stdout
    subjects = dict(line.split(" ", 1) for line in log.splitlines())
    for fid, short in alias.items():
        if fid.startswith("_"):
            continue
        fixes.setdefault(fid, []).append((short, subjects.get(short, "(see fixed-by.json)")))
    return fixes


def render(out):
    surv, verd, fixes = survey(), verdicts(), aliased_fixes(fix_commits())
    rows = []
    for fid, (dim, sev0, title) in surv.items():
        v = verd.get(fid, {})
        sev1 = v.get("severity_final", "?")
        status = v.get("status", "unjudged")
        commits = fixes.get(fid, [])
        fix = "; ".join(f"`{h}` {s}" for h, s in commits) if commits else "open"
        rows.append((dim, sev1, sev0, fid, title, status, fix))
    rows.sort(key=lambda r: (r[0], r[1], r[3]))

    tally = Counter()
    for dim, sev1, sev0, fid, title, status, fix in rows:
        tally[(dim, sev1, "fixed" if fix != "open" else "open")] += 1
    out("| dimension | S1 fixed/open | S2 fixed/open | S3 fixed/open |")
    out("|---|---|---|---|")
    for dim in sorted({r[0] for r in rows}):
        cells = [f"{tally[(dim, sev, 'fixed')]}/{tally[(dim, sev, 'open')]}"
                 for sev in ("S1", "S2", "S3")]
        out(f"| {dim} | " + " | ".join(cells) + " |")
    total_fixed = sum(1 for r in rows if r[6] != "open")
    out(f"\n{len(rows)} findings, {total_fixed} fixed, {len(rows) - total_fixed} open.\n")

    out("| dimension | finding | survey | final | verdict | fix |")
    out("|---|---|---|---|---|---|")
    for dim, sev1, sev0, fid, title, status, fix in rows:
        t = title if len(title) <= 80 else title[:77] + "..."
        out(f"| {dim} | `{fid}` {t} | {sev0} | {sev1} | {status} | {fix} |")


def main():
    if DOC is None:
        render(print)
        return
    lines = []
    render(lines.append)
    text = open(DOC).read()
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    open(DOC, "w").write(head + BEGIN + "\n" + "\n".join(lines) + "\n" + END + tail)
    print(f"{DOC}: tables regenerated")


if __name__ == "__main__":
    main()
