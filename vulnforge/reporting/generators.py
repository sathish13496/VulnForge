"""
VulnForge JSON Report Generator

Exports scan results as a structured JSON file for SIEM
integration and programmatic analysis.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from vulnforge.config import REPORTS_DIR
from vulnforge.core.target import Target


class JSONReporter:
    """Generate JSON reports from scan results."""

    def generate(self, target: Target, output_path: Optional[Path] = None) -> Path:
        """
        Generate a JSON report file.

        Args:
            target: Target with scan results
            output_path: Optional custom output path

        Returns:
            Path to the generated JSON file
        """
        if output_path is None:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = REPORTS_DIR / f"vulnforge_report_{target.ip}_{timestamp}.json"

        report_data = {
            "report_metadata": {
                "tool": "VulnForge",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "scan_id": target.scan_id,
            },
            "target": {
                "ip": target.ip,
                "hostname": target.hostname,
                "os_name": target.os_name,
                "os_family": target.os_family,
                "kernel_version": target.kernel_version,
                "is_alive": target.is_alive,
            },
            "scan_info": {
                "scan_type": target.scan_type,
                "port_range": target.port_range,
                "modules_selected": target.modules_selected,
                "start_time": target.start_time.isoformat() if target.start_time else None,
                "end_time": target.end_time.isoformat() if target.end_time else None,
                "elapsed_time": target.elapsed_time,
                "status": target.scan_status.value,
            },
            "summary": {
                "total_findings": target.total_findings,
                "severity_counts": target.severity_counts,
                "open_ports": len(target.open_ports),
            },
            "services": [s.to_dict() for s in target.services],
            "findings": [f.to_dict() for f in target.findings],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return output_path


class HTMLReporter:
    """Generate standalone HTML reports from scan results."""

    def generate(self, target: Target, output_path: Optional[Path] = None) -> Path:
        """Generate an HTML report file."""
        if output_path is None:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = REPORTS_DIR / f"vulnforge_report_{target.ip}_{timestamp}.html"

        html_content = self._build_html(target)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _build_html(self, target: Target) -> str:
        """Build the HTML report content."""
        severity_colors = {
            "critical": "#ff2d55",
            "high": "#ff6b35",
            "medium": "#ffbe0b",
            "low": "#06d6a0",
            "info": "#00d4ff",
        }

        findings_rows = ""
        for f in target.findings:
            color = severity_colors.get(f.severity.value, "#64748b")
            findings_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:700;">{f.severity.value.upper()}</span></td>
                <td>{f.title}</td>
                <td>{f.module}</td>
                <td><code>{f.cve_id or '—'}</code></td>
                <td><strong>{f.cvss_score}</strong></td>
                <td>{f.status.value}</td>
            </tr>
            <tr>
                <td colspan="6" style="padding:8px 16px 16px;border-top:none;">
                    <div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:14px;">
                        <p style="margin-bottom:6px;"><strong style="color:#94a3b8;">Description:</strong> {f.description or 'N/A'}</p>
                        {'<p style="margin-bottom:6px;"><strong style="color:#94a3b8;">Evidence:</strong> <code>' + f.evidence + '</code></p>' if f.evidence else ''}
                        {'<p><strong style="color:#06d6a0;">Remediation:</strong> ' + f.remediation + '</p>' if f.remediation else ''}
                    </div>
                </td>
            </tr>"""

        counts = target.severity_counts

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnForge Report — {target.ip}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0a0e1a; color: #e2e8f0; padding: 40px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ font-size: 28px; margin-bottom: 8px; color: #fff; }}
        h2 {{ font-size: 20px; margin: 30px 0 15px; color: #fff; }}
        .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 20px 0; }}
        .stat {{ background: #1a2235; border-radius: 10px; padding: 20px; text-align: center;
                 border: 1px solid rgba(255,255,255,0.06); }}
        .stat-value {{ font-size: 32px; font-weight: 900; }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a2235;
                 border-radius: 10px; overflow: hidden; margin-top: 15px; }}
        th {{ background: rgba(0,0,0,0.2); padding: 12px 16px; text-align: left;
              font-size: 11px; text-transform: uppercase; color: #94a3b8; }}
        td {{ padding: 12px 16px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 13px; }}
        code {{ background: rgba(0,212,255,0.08); padding: 2px 6px; border-radius: 4px;
                font-size: 12px; color: #00d4ff; }}
        .footer {{ text-align: center; margin-top: 40px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VulnForge Security Report</h1>
        <p class="meta">
            Target: <strong>{target.ip}</strong> ({target.os_name or 'Unknown OS'}) |
            Scan Type: <strong>{target.scan_type.upper()}</strong> |
            Duration: <strong>{target.elapsed_time}</strong> |
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </p>

        <h2>Summary</h2>
        <div class="stats">
            <div class="stat"><div class="stat-value" style="color:#ff2d55;">{counts.get('critical',0)}</div><div class="stat-label">Critical</div></div>
            <div class="stat"><div class="stat-value" style="color:#ff6b35;">{counts.get('high',0)}</div><div class="stat-label">High</div></div>
            <div class="stat"><div class="stat-value" style="color:#ffbe0b;">{counts.get('medium',0)}</div><div class="stat-label">Medium</div></div>
            <div class="stat"><div class="stat-value" style="color:#06d6a0;">{counts.get('low',0)}</div><div class="stat-label">Low</div></div>
            <div class="stat"><div class="stat-value" style="color:#00d4ff;">{counts.get('info',0)}</div><div class="stat-label">Info</div></div>
        </div>

        <h2>Open Ports ({len(target.open_ports)})</h2>
        <table>
            <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th><th>State</th></tr></thead>
            <tbody>
                {''.join(f'<tr><td>{s.port}</td><td>{s.protocol.upper()}</td><td>{s.service_name}</td><td>{s.product} {s.version}</td><td>{s.state}</td></tr>' for s in target.services)}
            </tbody>
        </table>

        <h2>Findings ({target.total_findings})</h2>
        <table>
            <thead><tr><th>Severity</th><th>Finding</th><th>Module</th><th>CVE</th><th>CVSS</th><th>Status</th></tr></thead>
            <tbody>{findings_rows}</tbody>
        </table>

        <div class="footer">
            Generated by VulnForge v1.0.0 — Linux Security Misconfiguration Discovery Framework
        </div>
    </div>
</body>
</html>"""
