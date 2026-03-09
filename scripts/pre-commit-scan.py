#!/usr/bin/env python3
"""
Pre-commit hook: run security scanner on staged Python files.
Usage: pre-commit-scan.py file1.py file2.py ...
Exits 1 if any scan finds issues at or above fail_on severity.
"""
import os
import sys
from pathlib import Path

# Run from repo root so scanner and config are found
repo_root = Path(__file__).resolve().parent.parent
os.chdir(repo_root)
sys.path.insert(0, str(repo_root))

from scanner import (
    load_config,
    scan_file,
    load_baseline,
    apply_baseline,
    should_fail,
    build_report,
)
from dotenv import load_dotenv
from google import genai

load_dotenv(repo_root / ".env")

def main():
    if len(sys.argv) < 2:
        return 0  # nothing to scan
    paths = [p for p in sys.argv[1:] if Path(p).suffix == ".py" and Path(p).is_file()]
    if not paths:
        return 0
    config = load_config(None)
    api_key = os.getenv(config["api_key_env"])
    if not api_key:
        print("security-scanner: GOOGLE_API_KEY not set, skipping scan.", file=sys.stderr)
        return 0
    client = genai.Client(api_key=api_key)
    model = config["model"]
    rules = config.get("rules")
    fail_on = config["fail_on"]
    baseline_path = os.getenv("SECURITY_SCANNER_BASELINE")
    findings = []
    for p in paths:
        findings.extend(scan_file(client, model, p, rules=rules, verbose=False))
    findings_for_exit = findings
    if baseline_path and Path(baseline_path).is_file():
        baseline_sigs = load_baseline(baseline_path)
        findings, new_findings = apply_baseline(findings, baseline_sigs)
        findings_for_exit = new_findings
    if should_fail(findings_for_exit, fail_on):
        print("security-scanner: findings at or above fail_on severity. Commit blocked.", file=sys.stderr)
        for f in findings_for_exit:
            if (f.get("severity") or "").lower() in {s.lower() for s in fail_on}:
                print(f"  {f.get('file')}:{f.get('line')} [{f.get('severity')}] {f.get('type')}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
