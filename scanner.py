"""
Security scanner: scan source files (Python / JavaScript / TypeScript / Java)
for security vulnerabilities using Gemini.

Supports single file, directory, JSON/HTML reports, and config file.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
import yaml

from reports import SCANNER_VERSION, build_report, write_html_report, write_json_report
from rules import run_rules_on_file, apply_rule_replacements

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "api_key_env": "GOOGLE_API_KEY",
    "model": "gemini-2.5-flash",
    # Default: common backend/frontend extensions
    "include": [
        "**/*.py",
        "**/*.js",
        "**/*.jsx",
        "**/*.ts",
        "**/*.tsx",
        "**/*.java",
    ],
    "exclude": ["**/venv/**", "**/__pycache__/**", "**/.git/**", "**/node_modules/**"],
    "fail_on": ["critical", "high"],
    "enable_cache": True,
    "cache_file": ".scanner-cache.json",
    "rate_limit_rps": 2.0,
}


def load_config(path: str | Path | None) -> dict:
    """Load config from YAML file; merge with defaults."""
    config = DEFAULT_CONFIG.copy()
    if path is None:
        for name in ("security-scanner.yaml", ".security-scanner.yaml"):
            if Path(name).is_file():
                path = name
                break
    if path and Path(path).is_file():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for k, v in data.items():
            if k in config and v is not None:
                config[k] = v
    return config


# ---------------------------------------------------------------------------
# LLM prompt and parsing
# ---------------------------------------------------------------------------

SECURITY_PROMPT = """Analyze this {language} code for security vulnerabilities.

Respond with a single JSON array. Each item must have exactly these keys:
- "severity": one of "CRITICAL", "HIGH", "MEDIUM", "LOW"
- "type": short vulnerability name (e.g. "SQL Injection")
- "description": one sentence explaining the issue
- "line": line number if you can infer it, else null
- "impact": one sentence on potential damage
- "fix": secure code snippet (or null if no simple fix)

If there are no issues, respond with: []

Output only the JSON array, no other text.

Code:
{code}
"""


def _parse_findings_json(text: str) -> list[dict]:
    """Extract and parse JSON array from model response."""
    text = (text or "").strip()
    # Try raw parse
    try:
        out = json.loads(text)
        if isinstance(out, list):
            return out
        if isinstance(out, dict) and "findings" in out:
            return out["findings"]
        return []
    except json.JSONDecodeError:
        pass
    # Try extract from ```json ... ```
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if m:
        try:
            out = json.loads(m.group(1).strip())
            return out if isinstance(out, list) else []
        except json.JSONDecodeError:
            pass
    # Try find [ ... ] array
    m = re.search(r"\[\s*\{[\s\S]*\}\s*\]", text)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return []


def _normalize_finding(f: dict, filepath: str) -> dict:
    """Ensure finding has file and standard keys."""
    return {
        "file": filepath,
        "line": f.get("line"),
        "severity": (f.get("severity") or "LOW").upper(),
        "type": f.get("type") or "Unknown",
        "description": f.get("description") or "",
        "impact": f.get("impact") or "",
        "fix": f.get("fix"),
    }


# ---------------------------------------------------------------------------
# LLM rate limiting
# ---------------------------------------------------------------------------

_LAST_LLM_CALL: float | None = None


def _respect_rate_limit(rate_limit_rps: float | None) -> None:
    if not rate_limit_rps or rate_limit_rps <= 0:
        return
    global _LAST_LLM_CALL
    now = time.time()
    min_interval = 1.0 / rate_limit_rps
    if _LAST_LLM_CALL is not None:
        elapsed = now - _LAST_LLM_CALL
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    _LAST_LLM_CALL = time.time()


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_file(
    client: genai.Client,
    model: str,
    filepath: str | Path,
    *,
    rules: list[dict] | None = None,
    auto_fix: bool = False,
    rate_limit_rps: float | None = None,
    cache: dict | None = None,
    cache_enabled: bool = False,
    verbose: bool = True,
) -> list[dict]:
    """Scan a single file; return list of findings (custom rules + LLM)."""
    path = Path(filepath)
    if not path.is_file():
        return []
    try:
        code = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if verbose:
        print(f"Scanning: {path}", file=sys.stderr)

    # Auto-fix using custom rules with replacements (no LLM).
    if auto_fix and rules:
        new_code, applied = apply_rule_replacements(code, rules)
        if applied and new_code != code:
            if verbose:
                for a in applied:
                    print(
                        f"Auto-fix: applied rule {a.get('id') or a.get('name')} "
                        f"({a.get('count')} change(s)) in {path}",
                        file=sys.stderr,
                    )
            try:
                path.write_text(new_code, encoding="utf-8")
                code = new_code
            except OSError:
                # If we can't write, continue with original content (no auto-fix)
                pass

    # Cache key is file path + content hash.
    findings: list[dict] = []
    content_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    cache_key = str(path.resolve())
    if cache_enabled and cache is not None:
        cached_entry = cache.get(cache_key)
        if cached_entry and cached_entry.get("hash") == content_hash:
            cached_findings = cached_entry.get("findings") or []
            if verbose:
                print(f"Using cache for {path}", file=sys.stderr)
            return cached_findings

    # Local rules (always run on current content)
    if rules:
        findings.extend(run_rules_on_file(code, path, rules))

    # LLM scan with simple rate limiting
    _respect_rate_limit(rate_limit_rps)
    suffix = path.suffix.lower()
    if suffix == ".py":
        language = "Python"
    elif suffix in (".js", ".jsx"):
        language = "JavaScript"
    elif suffix in (".ts", ".tsx"):
        language = "TypeScript"
    elif suffix == ".java":
        language = "Java"
    else:
        language = "source"

    try:
        response = client.models.generate_content(
            model=model,
            contents=SECURITY_PROMPT.format(language=language, code=code),
        )
    except Exception as e:
        msg = str(e)
        if (
            "RESOURCE_EXHAUSTED" in msg
            or "429" in msg
            or "quota" in msg.lower()
        ):
            if verbose:
                print(
                    f"Warning: quota exhausted while scanning {path}: {e}",
                    file=sys.stderr,
                )
            # Soft-fail on quota errors: skip LLM findings for this file
            return findings
        raise

    text = getattr(response, "text", None) or ""
    raw = _parse_findings_json(text)
    findings.extend([_normalize_finding(f, str(path)) for f in raw])

    if cache_enabled and cache is not None:
        cache[cache_key] = {"hash": content_hash, "findings": findings}

    return findings


def _should_include(path: Path, include_globs: list[str], exclude_globs: list[str]) -> bool:
    """Whether path should be included (relative to cwd or a given root)."""
    try:
        rel = path.resolve().relative_to(Path.cwd())
    except ValueError:
        rel = path
    s = str(rel).replace("\\", "/")
    for pat in exclude_globs:
        if _glob_matches(pat, s):
            return False
    for pat in include_globs:
        if _glob_matches(pat, s):
            return True
    return bool(include_globs)


def _glob_matches(pat: str, s: str) -> bool:
    """Simple glob match: ** = any path, * = any segment."""
    if "**" in pat:
        re_pat = pat.replace("**", ".*").replace("*", "[^/]*")
    else:
        re_pat = pat.replace("*", "[^/]*")
    re_pat = re_pat.replace(".", r"\.")
    return bool(re.fullmatch(re_pat, s, re.IGNORECASE))


def collect_files(root: str | Path, include: list[str], exclude: list[str]) -> list[Path]:
    """Collect files under root that pass include/exclude globs."""
    root = Path(root).resolve()
    out = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        s = str(rel).replace("\\", "/")
        skip = False
        for pat in exclude:
            if _glob_matches(pat, s):
                skip = True
                break
        if skip:
            continue
        if include:
            if any(_glob_matches(pat, s) for pat in include):
                out.append(path)
        else:
            out.append(path)
    return sorted(out)


def scan_directory(
    client: genai.Client,
    model: str,
    root: str | Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    rules: list[dict] | None = None,
    auto_fix: bool = False,
    rate_limit_rps: float | None = None,
    cache: dict | None = None,
    cache_enabled: bool = False,
    verbose: bool = True,
) -> list[dict]:
    """Scan all included files under root; return combined findings."""
    include = include or DEFAULT_CONFIG["include"]
    exclude = exclude or DEFAULT_CONFIG["exclude"]
    paths = collect_files(root, include, exclude)
    if verbose:
        print(f"Found {len(paths)} file(s) under {root}", file=sys.stderr)
    findings = []
    for p in paths:
        findings.extend(
            scan_file(
                client,
                model,
                p,
                rules=rules,
                auto_fix=auto_fix,
                rate_limit_rps=rate_limit_rps,
                cache=cache,
                cache_enabled=cache_enabled,
                verbose=verbose,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def _finding_signature(f: dict) -> tuple:
    """Stable signature for baseline matching (file, type, description)."""
    raw_path = f.get("file") or ""
    p = Path(raw_path)
    try:
        # Normalize to path relative to current working directory (repo root in CI/local)
        rel = p.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        # If the file is outside the cwd or cannot be relativized, fall back to the original path
        rel = p
    normalized_path = str(rel).replace("\\", "/")
    return (
        normalized_path,
        (f.get("type") or "").strip(),
        (f.get("description") or "").strip()[:200],
    )


def load_baseline(path: str | Path) -> set[tuple]:
    """Load baseline report JSON; return set of finding signatures."""
    path = Path(path)
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    findings = data.get("findings") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    return {_finding_signature(f) for f in findings}


def apply_baseline(findings: list[dict], baseline_sigs: set[tuple]) -> tuple[list[dict], list[dict]]:
    """Mark each finding with 'new' and return (all_findings_with_new_flag, new_findings_only)."""
    all_with_flag = []
    new_only = []
    for f in findings:
        sig = _finding_signature(f)
        is_new = sig not in baseline_sigs
        out = {**f, "new": is_new}
        all_with_flag.append(out)
        if is_new:
            new_only.append(out)
    return all_with_flag, new_only


# ---------------------------------------------------------------------------
# Exit code and CLI
# ---------------------------------------------------------------------------

def should_fail(findings: list[dict], fail_on: list[str]) -> bool:
    """True if any finding has severity in fail_on."""
    fail_set = {s.lower() for s in fail_on}
    for f in findings:
        if (f.get("severity") or "").lower() in fail_set:
            return True
    return False


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Scan source files (Python / JavaScript / TypeScript / Java) for security vulnerabilities (Gemini-powered).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output report path (extension determines format: .json or .html)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "html", "both"),
        default="json",
        help="Report format when using --output (default: json)",
    )
    parser.add_argument(
        "--fail-on",
        metavar="SEV",
        nargs="+",
        default=None,
        help="Severities that cause exit 1 (e.g. critical high). Default from config.",
    )
    parser.add_argument(
        "-c", "--config",
        help="Config file path (default: security-scanner.yaml or .security-scanner.yaml)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Less stderr output",
    )
    parser.add_argument(
        "-b", "--baseline",
        metavar="FILE",
        help="Baseline report JSON; only findings not in baseline cause exit 1",
    )
    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Apply simple regex-based fixes from custom rules before scanning",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    api_key = os.getenv(config["api_key_env"])
    if not api_key:
        print("Error: API key not set. Set GOOGLE_API_KEY or configure api_key_env in config.", file=sys.stderr)
        sys.exit(2)
    client = genai.Client(api_key=api_key)
    model = config["model"]
    fail_on = args.fail_on or config["fail_on"]
    verbose = not args.quiet
    cache_enabled = bool(config.get("enable_cache"))
    cache_file = Path(config.get("cache_file") or ".scanner-cache.json")
    rate_limit_rps = float(config.get("rate_limit_rps") or 0) or None
    cache: dict | None = None
    if cache_enabled and cache_file.is_file():
        try:
            cache = json.loads(cache_file.read_text(encoding="utf-8")) or {}
        except (OSError, json.JSONDecodeError):
            cache = {}
    elif cache_enabled:
        cache = {}

    target = Path(args.target)
    rules = config.get("rules")
    if target.is_file():
        findings = scan_file(
            client,
            model,
            target,
            rules=rules,
            auto_fix=args.auto_fix,
            rate_limit_rps=rate_limit_rps,
            cache=cache,
            cache_enabled=cache_enabled,
            verbose=verbose,
        )
        root = str(target.parent)
    elif target.is_dir():
        findings = scan_directory(
            client,
            model,
            target,
            include=config.get("include"),
            exclude=config.get("exclude"),
            rules=rules,
            auto_fix=args.auto_fix,
            rate_limit_rps=rate_limit_rps,
            cache=cache,
            cache_enabled=cache_enabled,
            verbose=verbose,
        )
        root = str(target.resolve())
    else:
        print(f"Error: not a file or directory: {target}", file=sys.stderr)
        sys.exit(2)

    # Baseline: only new findings affect exit code
    findings_for_exit = findings
    if args.baseline:
        baseline_sigs = load_baseline(args.baseline)
        findings, new_findings = apply_baseline(findings, baseline_sigs)
        findings_for_exit = new_findings
        if verbose and baseline_sigs:
            print(f"Baseline: {len(baseline_sigs)} known findings; {len(new_findings)} new", file=sys.stderr)

    report = build_report(root, findings, scanner_version=SCANNER_VERSION)

    # Persist cache to disk
    if cache_enabled and cache is not None:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cache), encoding="utf-8")
        except OSError:
            if verbose:
                print(f"Warning: could not write cache file {cache_file}", file=sys.stderr)
    out_path = args.output

    if out_path:
        out_path = Path(out_path)
        if args.format == "both":
            write_json_report(report, out_path.with_suffix(".json"))
            write_html_report(report, out_path.with_suffix(".html"))
            if verbose:
                print(f"Wrote JSON and HTML reports", file=sys.stderr)
        elif args.format == "html":
            write_html_report(report, out_path)
            if verbose:
                print(f"Wrote HTML report: {out_path}", file=sys.stderr)
        else:
            write_json_report(report, out_path)
            if verbose:
                print(f"Wrote JSON report: {out_path}", file=sys.stderr)
    else:
        # Default: print JSON to stdout
        print(json.dumps(report, indent=2))

    if should_fail(findings_for_exit, fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
