"""Custom regex-based rules run locally (no API).

Supports both detection-only rules and simple auto-fix rules
using regex replacements.
"""

import re
from pathlib import Path


def _line_at_offset(text: str, offset: int) -> int:
    """Return 1-based line number for character offset in text."""
    return text.count("\n", 0, offset) + 1


def run_rules_on_file(content: str, filepath: str | Path, rules: list[dict]) -> list[dict]:
    """Run custom regex rules on file content. Return list of findings (same schema as LLM).

    Rules may define:
    - pattern (required)
    - severity, name/id, message, impact, fix
    - replacement: optional regex replacement string for auto-fix mode
    """
    path_str = str(Path(filepath).resolve())
    findings = []
    for rule in rules or []:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            flags = re.MULTILINE
            if rule.get("case_insensitive"):
                flags |= re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error:
            continue
        for m in rx.finditer(content):
            line = _line_at_offset(content, m.start())
            findings.append({
                "file": path_str,
                "line": line,
                "severity": (rule.get("severity") or "MEDIUM").upper(),
                "type": rule.get("name") or rule.get("id") or "Custom rule",
                "description": rule.get("message") or f"Matches pattern: {pattern[:50]}...",
                "impact": rule.get("impact", ""),
                "fix": rule.get("fix"),
                "rule_id": rule.get("id"),
            })
    return findings


def apply_rule_replacements(content: str, rules: list[dict]) -> tuple[str, list[dict]]:
    """Apply regex replacements for rules that define \"replacement\".

    Returns (new_content, applied_rules_metadata).
    """
    new_content = content
    applied: list[dict] = []
    for rule in rules or []:
        pattern = rule.get("pattern")
        replacement = rule.get("replacement")
        if not pattern or replacement is None:
            continue
        try:
            flags = re.MULTILINE
            if rule.get("case_insensitive"):
                flags |= re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error:
            continue
        new_text, count = rx.subn(replacement, new_content)
        if count > 0:
            applied.append({
                "id": rule.get("id"),
                "name": rule.get("name"),
                "pattern": pattern,
                "count": count,
            })
            new_content = new_text
    return new_content, applied
