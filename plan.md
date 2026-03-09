# Security Scanner — Roadmap

## Current State
- Single-file scan via `python scanner.py <filepath>`
- Gemini-based analysis; output is colored text only
- No structured data, no directory mode, no config or CI

---

## Implementation Order

### Phase 1: Foundation ✅
- [x] **Structured output + JSON report** — LLM returns parseable JSON; single schema for all consumers
- [x] **CLI + config file** — One entrypoint; config-driven (paths, API, fail_on) via `security-scanner.yaml`
- [x] **Directory scan with exclude list** — Walk `.py` files; skip `venv/`, `__pycache__/`, `.git/`; include/exclude globs in config
- [x] **HTML report + exit codes** — Generate HTML from JSON; exit 0 (ok), 1 (findings), 2 (error)

### Phase 2: Production Hardening ✅ (partial)
- [x] **Custom rules** — YAML rules (regex, severity, message, fix); run per-file before LLM
- [x] **CI integration** — Pre-commit hook (`scripts/pre-commit-scan.py` + `.pre-commit-config.yaml`) + GitHub Action (`.github/workflows/security-scan.yml`)
- [x] **Baseline file** — `-b/--baseline`; only new findings (vs baseline) cause exit 1; HTML shows "New" badge
- [ ] **Auto-fix mode** — `--auto-fix` / `fix` subcommand; show diff, optional apply with backup
- [ ] **Rate limiting + retries** — Throttle API calls; exponential backoff on 429/5xx
- [ ] **Caching** — Hash file content; skip unchanged files for faster re-runs

### Phase 3: Polish
- [ ] **Packaging** — `pyproject.toml`, entry point `security-scanner`
- [ ] **Tests** — Assert expected findings on `vulnerable.py` and fixtures
- [ ] **Documentation** — README with install, config, CLI, CI example

---

## Report Schema (JSON)

```json
{
  "version": "1.0",
  "scanner_version": "0.1.0",
  "timestamp": "ISO8601",
  "root": "/path/to/repo",
  "summary": { "critical": 0, "high": 1, "medium": 2, "low": 0 },
  "findings": [
    {
      "file": "src/auth.py",
      "line": 12,
      "severity": "HIGH",
      "type": "SQL Injection",
      "description": "...",
      "impact": "...",
      "fix": "code snippet or null"
    }
  ]
}
```

## Config File (`security-scanner.yaml`)

- `api_key_env`: env var name for API key (default: GOOGLE_API_KEY)
- `model`: Gemini model name
- `include` / `exclude`: globs for directory scan
- `fail_on`: severities that cause exit code 1 (default: critical, high)
- (Later) `rules`: custom rule definitions

## Exit Codes

- `0` — No findings above threshold, or scan succeeded with only lower severities
- `1` — Findings at or above `fail_on` severity
- `2` — Error (missing config, API failure, invalid args)
