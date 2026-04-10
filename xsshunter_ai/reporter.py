"""Report generator — JSON and HTML output."""

import json
import html
import os
from datetime import datetime, timezone
from xsshunter_ai.utils import success


class Reporter:
    """Collects scan findings and generates reports."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.start_time = datetime.now(timezone.utc)

    def add_finding(self, injection_point, payload, result_label, status_code, snippet):
        self.findings.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": injection_point.method,
            "param_name": injection_point.param_name,
            "param_type": injection_point.param_type,
            "target": injection_point.form_action or injection_point.url,
            "payload": payload,
            "result": result_label,
            "status_code": status_code,
            "snippet": snippet[:500],
        })

    def save_json(self, path):
        report = {
            "tool": "xsshunter",
            "version": "0.1.0",
            "target_url": self.target_url,
            "scan_start": self.start_time.isoformat(),
            "scan_end": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        success(f"JSON report saved: {path}")

    def save_html(self, path):
        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            severity_class = "critical" if f["result"] in ("reflected", "executed") else "warning"
            findings_html += f"""
            <tr class="{severity_class}">
                <td>{i}</td>
                <td>{html.escape(f["method"])}</td>
                <td>{html.escape(f["param_type"])}:{html.escape(f["param_name"])}</td>
                <td><code>{html.escape(f["payload"][:100])}</code></td>
                <td><span class="badge {f["result"]}">{html.escape(f["result"])}</span></td>
                <td>{f["status_code"]}</td>
                <td><details><summary>Show</summary><pre>{html.escape(f["snippet"])}</pre></details></td>
            </tr>"""

        # Count by result type
        result_counts = {}
        for f in self.findings:
            result_counts[f["result"]] = result_counts.get(f["result"], 0) + 1
        stats_html = " | ".join(f"{k}: {v}" for k, v in sorted(result_counts.items()))

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>XSSHUNTER Report — {html.escape(self.target_url)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    h1 {{ color: #f85149; margin-bottom: 0.5rem; }}
    .meta {{ color: #8b949e; margin-bottom: 1.5rem; }}
    .stats {{ background: #161b22; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-family: monospace; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
    th {{ background: #21262d; color: #f0f6fc; padding: 0.75rem; text-align: left; font-size: 0.85rem; text-transform: uppercase; }}
    td {{ padding: 0.75rem; border-top: 1px solid #21262d; font-size: 0.9rem; vertical-align: top; }}
    tr.critical {{ border-left: 3px solid #f85149; }}
    tr.warning {{ border-left: 3px solid #d29922; }}
    code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; word-break: break-all; }}
    pre {{ background: #0d1117; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; max-height: 200px; }}
    .badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }}
    .badge.reflected {{ background: #f8514933; color: #f85149; }}
    .badge.executed {{ background: #f8514966; color: #ff7b72; }}
    .badge.filtered {{ background: #d2992233; color: #d29922; }}
    .badge.blocked {{ background: #8b949e33; color: #8b949e; }}
    .badge.not_reflected {{ background: #8b949e22; color: #8b949e; }}
    .badge.encoded_back {{ background: #d2992244; color: #e3b341; }}
    details > summary {{ cursor: pointer; color: #58a6ff; }}
</style>
</head>
<body>
    <h1>XSSHUNTER Scan Report</h1>
    <p class="meta">
        Target: <strong>{html.escape(self.target_url)}</strong><br>
        Scan started: {self.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")}<br>
        Report generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
    </p>
    <div class="stats">{stats_html or "No findings"}</div>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Method</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>Result</th>
                <th>Status</th>
                <th>Snippet</th>
            </tr>
        </thead>
        <tbody>
            {findings_html or "<tr><td colspan='7'>No findings recorded.</td></tr>"}
        </tbody>
    </table>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(page)
        success(f"HTML report saved: {path}")
