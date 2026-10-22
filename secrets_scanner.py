#!/usr/bin/env python3
"""Secrets scanner.

Looks through files for things that should never be committed: cloud keys,
private keys, tokens, and passwords written straight into code.
Standard library only. Nothing is sent anywhere, and the full secret is
never printed (only the first 4 characters).

Usage:
    python3 secrets_scanner.py sample_files/
    python3 secrets_scanner.py my_project/ --format json --min-severity high
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Folders that never hold your own code, or that hold huge generated files.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
MAX_FILE_BYTES = 1_000_000

# Add this comment to a line to tell the scanner it is a known, safe value.
IGNORE_MARKER = "secrets-scanner: ignore"

# Values that are obviously not real secrets. Only used by the generic rule,
# because the specific rules (AWS keys, private keys...) have a fixed shape.
PLACEHOLDER_HINTS = (
    "changeme", "change_me", "example", "placeholder", "your_", "your-",
    "xxxx", "dummy", "<", "${", "{{", "os.environ", "getenv",
)
PLACEHOLDER_WORDS = {"password", "secret", "token", "none", "null", "undefined"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    pattern: "re.Pattern"
    advice: str
    group: int = 0  # which part of the match is the secret itself
    check_placeholder: bool = False


RULES = [
    Rule(
        "aws-access-key-id", "high", "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "Deactivate the key in IAM, create a new one, and keep it out of code.",
        group=1,
    ),
    Rule(
        "aws-secret-access-key", "critical", "AWS secret access key",
        re.compile(
            r"aws_?secret_?access_?key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
            re.IGNORECASE,
        ),
        "Treat the key as stolen: deactivate it now and create a new one.",
        group=1,
    ),
    Rule(
        "private-key", "critical", "Private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "Remove the key from the file, create a new key pair, and retire this one.",
    ),
    Rule(
        "github-token", "high", "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        "Revoke the token in GitHub settings and create a new one.",
        group=1,
    ),
    Rule(
        "slack-token", "high", "Slack token",
        re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        "Revoke the token in Slack and create a new one.",
        group=1,
    ),
    Rule(
        "password-in-url", "high", "Password inside a web address",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:([^/\s:@\"']{4,})@"),
        "Move the password to an environment variable or a secrets manager.",
        group=1,
    ),
    Rule(
        "json-web-token", "medium", "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "A token can be reused until it expires. Check it is not a live one.",
        group=1,
    ),
    Rule(
        "hardcoded-secret", "medium", "Password or key written into the file",
        re.compile(
            r"(?:password|passwd|pwd|secret|api_?key|token)[\"']?\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']",
            re.IGNORECASE,
        ),
        "Read it from an environment variable or a secrets manager instead.",
        group=1,
        check_placeholder=True,
    ),
]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    severity: str
    title: str
    preview: str
    advice: str


def mask(secret):
    """Show only the first 4 characters so the report is not a leak itself."""
    if len(secret) <= 4:
        return "****"
    return secret[:4] + "****"


def looks_like_placeholder(value):
    lowered = value.lower()
    if lowered in PLACEHOLDER_WORDS:
        return True
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def scan_text(text, path="<text>"):
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                secret = match.group(rule.group)
                if rule.check_placeholder and looks_like_placeholder(secret):
                    continue
                findings.append(Finding(
                    path=str(path), line=number, rule_id=rule.rule_id,
                    severity=rule.severity, title=rule.title,
                    preview=mask(secret) if rule.group else match.group(0),
                    advice=rule.advice,
                ))
    return findings


def scan_file(path):
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        return []
    data = path.read_bytes()
    if b"\x00" in data[:2048]:  # binary file
        return []
    return scan_text(data.decode("utf-8", errors="replace"), path)


def collect_files(paths):
    for raw in paths:
        root = Path(raw)
        if root.is_file():
            yield root
        elif root.is_dir():
            for item in sorted(root.rglob("*")):
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                if item.is_file():
                    yield item
        else:
            raise FileNotFoundError(raw)


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line),
    )


def format_text(findings, files_scanned):
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.title} ({f.rule_id})")
        lines.append(f"  {f.path}:{f.line}   found: {f.preview}")
        lines.append(f"  fix: {f.advice}")
        lines.append("")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts
    )
    lines.append(
        f"Scanned {files_scanned} file(s): {len(findings)} finding(s)"
        + (f" ({summary})" if summary else "")
    )
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Find secrets that should not be in code."
    )
    parser.add_argument("paths", nargs="+", help="files or folders to scan")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--min-severity", choices=tuple(SEVERITY_ORDER), default="low",
        help="hide findings below this level (default: low)",
    )
    parser.add_argument(
        "--fail-on", choices=tuple(SEVERITY_ORDER), default="high",
        help="exit with code 1 if a finding is at or above this level (default: high)",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    all_findings = []
    scanned = 0
    try:
        for path in collect_files(args.paths):
            all_findings.extend(scan_file(path))
            scanned += 1
    except (OSError, FileNotFoundError) as error:
        print(f"error: could not read {error}", file=sys.stderr)
        return 2

    all_findings = sort_findings(all_findings)
    minimum = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= minimum]

    if args.format == "json":
        print(json.dumps([asdict(f) for f in shown], indent=2))
    else:
        print(format_text(shown, scanned))

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] >= threshold for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
