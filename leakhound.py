#!/usr/bin/env python3
"""LeakHound — find leaked secrets in a file tree without ever printing them.

Every finding reports only the file, line, rule name, and a short SHA-256
fingerprint of the matched value. The secret itself is never written to
stdout, stderr, or any report, so scan output is safe to keep in CI logs,
tickets, and chat. Fingerprints double as allowlist keys: suppress a false
positive by its hash, not by pasting the secret into a config file.

Single file. Python 3.10+. Standard library only. No network access.
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys

VERSION = "1.0.0"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle",
    "dist", "build", "target",
}
DEFAULT_MAX_BYTES = 1_000_000

RULES = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]
GENERIC = re.compile(
    r"""(?ix)\b(?:api[_-]?key|apikey|secret|token|password|passwd|auth)\b\s*[:=]\s*['"]?([^\s'"]{12,})['"]?"""
)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def diversity(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy / math.log2(min(n, 16)) if n > 1 else 0.0


def scan_line(line: str):
    """Yield (rule, matched_value) for a single line. Value stays internal."""
    for name, rx in RULES:
        for m in rx.finditer(line):
            yield name, m.group(0)
    for m in GENERIC.finditer(line):
        value = m.group(1)
        if diversity(value) >= 0.55:
            yield "generic-assignment", value


def is_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def load_allowlist(path):
    """Allowlist lines: a 12-hex fingerprint, or 'relpath:rule'."""
    fingerprints, path_rules = set(), set()
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if re.fullmatch(r"[0-9a-f]{12}", entry):
                fingerprints.add(entry)
            else:
                path_rules.add(entry)
    return fingerprints, path_rules


def scan_tree(root, max_bytes, allow_fps, allow_prs, self_paths):
    findings, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.abspath(full) in self_paths or os.path.islink(full):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                skipped.append({"path": rel, "reason": "unreadable"})
                continue
            if size > max_bytes:
                skipped.append({"path": rel, "reason": "over size cap"})
                continue
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                skipped.append({"path": rel, "reason": "unreadable"})
                continue
            if is_binary(data):
                skipped.append({"path": rel, "reason": "binary"})
                continue
            text = data.decode("utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                for rule, value in scan_line(line):
                    fp = fingerprint(value)
                    if fp in allow_fps or f"{rel}:{rule}" in allow_prs:
                        continue
                    findings.append({
                        "path": rel, "line": lineno, "rule": rule,
                        "fingerprint": fp,
                    })
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"], f["fingerprint"]))
    skipped.sort(key=lambda s: s["path"])
    return findings, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leakhound", description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--allow", metavar="FILE", help="Allowlist file (fingerprints or path:rule lines)")
    ap.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--version", action="version", version=f"leakhound {VERSION}")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"leakhound: not a directory: {args.path}", file=sys.stderr)
        return 2
    allow_fps, allow_prs = set(), set()
    self_paths = set()
    if args.allow:
        try:
            allow_fps, allow_prs = load_allowlist(args.allow)
        except OSError as exc:
            print(f"leakhound: cannot read allowlist: {exc}", file=sys.stderr)
            return 2
        self_paths.add(os.path.abspath(args.allow))

    root = os.path.abspath(args.path)
    findings, skipped = scan_tree(root, args.max_file_bytes, allow_fps, allow_prs, self_paths)

    if args.format == "json":
        print(json.dumps({
            "tool": "leakhound", "version": VERSION,
            "findings": findings, "skipped": skipped,
            "totals": {"findings": len(findings), "files_skipped": len(skipped)},
        }, indent=2, sort_keys=True))
    else:
        for f in findings:
            print(f"{f['path']}:{f['line']}: {f['rule']} [fp:{f['fingerprint']}]")
        print(f"leakhound: {len(findings)} finding(s), {len(skipped)} file(s) skipped",
              file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
