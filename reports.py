"""Generate JSON and HTML reports from scan findings."""

import json
from datetime import datetime
from pathlib import Path


SCANNER_VERSION = "0.1.0"


def build_report(root: str, findings: list[dict], scanner_version: str = SCANNER_VERSION) -> dict:
    """Build the full report dict with summary."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev in summary:
            summary[sev] += 1

    return {
        "version": "1.0",
        "scanner_version": scanner_version,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": str(Path(root).resolve()),
        "summary": summary,
        "findings": findings,
    }


def write_json_report(report: dict, path: str | Path) -> None:
    """Write report to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def write_html_report(report: dict, path: str | Path) -> None:
    """Write report to an HTML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = _render_html(report)
    path.write_text(html, encoding="utf-8")


def _render_html(report: dict) -> str:
    """Simple HTML template for the report."""
    s = report["summary"]
    findings = report["findings"]
    ts = report["timestamp"]

    rows = []
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        new_badge = ' <span class="badge new">New</span>' if f.get("new") else ""
        row = f"""
        <tr class="severity-{sev}">
            <td>{_esc(f.get("file", ""))}</td>
            <td>{f.get("line", "")}</td>
            <td><span class="badge {sev}">{sev}</span>{new_badge}</td>
            <td>{_esc(f.get("type", ""))}</td>
            <td>{_esc(f.get("description", ""))}</td>
            <td><pre>{_esc(f.get("fix") or "")}</pre></td>
        </tr>"""
        rows.append(row)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        :root {{ --critical: #c0392b; --high: #e67e22; --medium: #f39c12; --low: #27ae60; }}
        body {{ font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 1rem; }}
        h1 {{ margin-bottom: 0.5rem; }}
        .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
        .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
        .summary .stat {{ padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; }}
        .summary .critical {{ background: #fadbd8; color: var(--critical); }}
        .summary .high {{ background: #fdebd0; color: var(--high); }}
        .summary .medium {{ background: #fef9e7; color: var(--medium); }}
        .summary .low {{ background: #e8f8f5; color: var(--low); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eee; }}
        th {{ background: #f5f5f5; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; font-weight: 600; }}
        .badge.critical {{ background: var(--critical); color: #fff; }}
        .badge.high {{ background: var(--high); color: #fff; }}
        .badge.medium {{ background: var(--medium); color: #000; }}
        .badge.low {{ background: var(--low); color: #fff; }}
        .badge.new {{ background: #3498db; color: #fff; margin-left: 0.25rem; }}
        pre {{ margin: 0; font-size: 0.85rem; white-space: pre-wrap; }}
        .severity-critical {{ background: #fadbd8; }}
        .severity-high {{ background: #fdebd0; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <div class="meta">Generated {_esc(ts)} · Scanner v{_esc(report.get("scanner_version", ""))} · Root: {_esc(report.get("root", ""))}</div>
    <div class="summary">
        <span class="stat critical">Critical: {s.get("critical", 0)}</span>
        <span class="stat high">High: {s.get("high", 0)}</span>
        <span class="stat medium">Medium: {s.get("medium", 0)}</span>
        <span class="stat low">Low: {s.get("low", 0)}</span>
    </div>
    <table>
        <thead>
            <tr>
                <th>File</th>
                <th>Line</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Description</th>
                <th>Fix</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows) if rows else "<tr><td colspan=\"6\">No findings.</td></tr>"}
        </tbody>
    </table>
</body>
</html>"""


def _esc(s: str) -> str:
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
