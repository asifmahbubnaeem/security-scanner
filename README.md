# Security Scanner

Multi-language security scanner powered by Gemini. Scans Python, JavaScript/TypeScript, and Java source files in single files or whole directories, outputs JSON/HTML reports, and supports config and CI-friendly exit codes.

## Setup

```bash
pip install -r requirements.txt
```

Set your Gemini API key:

```bash
export GOOGLE_API_KEY=your_key
# or use a .env file (python-dotenv will load it)
```

## Usage

**Scan a single file (report to stdout as JSON):**
```bash
python scanner.py vulnerable.py
```

**Scan current directory:**
```bash
python scanner.py .
```

**Write reports to files:**
```bash
python scanner.py . -o report.json
python scanner.py . -o report.html --format html
python scanner.py . -o report --format both   # writes report.json and report.html
```

**CI: fail the run if there are high/critical findings (default):**
```bash
python scanner.py . -o report.json
# exit 1 if any critical or high finding
```

**Custom severities to fail on:**
```bash
python scanner.py . --fail-on critical high medium
```

**Use a config file (optional):**
```bash
python scanner.py . -c security-scanner.yaml -o report.json
```

Config is auto-loaded from `security-scanner.yaml` or `.security-scanner.yaml` in the current directory if `-c` is not set.

## Exit codes

- `0` — No findings at or above `--fail-on` severity
- `1` — At least one finding at or above `--fail-on` severity
- `2` — Error (missing API key, invalid target, etc.)

## Config (`security-scanner.yaml`)

See `security-scanner.yaml` in this repo. Options: `api_key_env`, `model`, `include`, `exclude`, `fail_on`.

## Custom rules

In `security-scanner.yaml` add a `rules` list. Each rule: `id`, `name`, `pattern` (regex), `severity`, `message`, optional `fix` and `case_insensitive`. Example:

```yaml
rules:
  - id: hardcoded-secret
    name: Hardcoded secret
    pattern: '(?i)(password|api_key|secret)\s*=\s*["\'][^"\']+["\']'
    severity: high
    message: Hardcoded credential detected
```

## Baseline (CI)

To fail only on **new** findings, create a baseline from a previous run and pass it:

```bash
python scanner.py . -o report.json    # first run
cp report.json security-baseline.json # save as baseline
# later:
python scanner.py . -o report.json -b security-baseline.json  # exit 1 only for new issues
```

In GitHub Actions, add `security-baseline.json` to the repo (or generate it once); the workflow uses it if present.

## CI integration

**Pre-commit** (scan staged Python files before commit):

```bash
pip install pre-commit
pre-commit install
# optional: SECURITY_SCANNER_BASELINE=security-baseline.json
```

**GitHub Actions:** Add `GOOGLE_API_KEY` to repo secrets. The workflow in `.github/workflows/security-scan.yml` runs on push/PR, uploads `report.json` as an artifact, and fails the job if there are high/critical findings (or new ones when using a baseline).
