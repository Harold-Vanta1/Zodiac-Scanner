"""Report management and data models for scan findings."""

import json
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    """Represents a vulnerability finding from a scan."""
    
    id: str
    type: str  # XSS, SQLi, LFI, SUBDOMAIN, etc.
    target: str  # Full URL or domain
    path: str
    parameter: Optional[str] = None
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    evidence: Optional[str] = None
    timestamp: str = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}


class ReportManager:
    """Manages scan reports with JSON and HTML export capabilities."""
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.metadata = {
            "report_schema_version": "1.0",
            "scanner_version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "scan_type": "unknown",
            "target": "",
        }
    
    def set_meta(self, metadata: Dict[str, Any]):
        """Set report metadata."""
        self.metadata.update(metadata)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the report."""
        self.findings.append(finding)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about findings."""
        severity_count = {}
        type_count = {}
        
        for finding in self.findings:
            severity_count[finding.severity] = severity_count.get(finding.severity, 0) + 1
            type_count[finding.type] = type_count.get(finding.type, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_count,
            "type_breakdown": type_count,
        }
    
    def save_json(self, path: str = "report.json"):
        """Save report as JSON."""
        report = {
            "metadata": self.metadata,
            "statistics": self.get_stats(),
            "findings": [asdict(finding) for finding in self.findings],
        }
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def save_html(self, path: str = "report.html", sanitize: bool = True):
        """Save report as HTML with sanitized content."""
        stats = self.get_stats()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zodiac Scan Report - {self.metadata.get('target', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .content {{
            padding: 40px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }}
        .stat-card .label {{
            color: #6c757d;
            margin-top: 5px;
        }}
        .findings {{
            margin-top: 40px;
        }}
        .finding {{
            background: #f8f9fa;
            border-left: 4px solid #2a5298;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
            transition: transform 0.2s;
        }}
        .finding:hover {{
            transform: translateX(5px);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-type {{
            font-size: 1.2em;
            font-weight: bold;
            color: #2a5298;
        }}
        .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .severity.CRITICAL {{ background: #dc3545; color: white; }}
        .severity.HIGH {{ background: #fd7e14; color: white; }}
        .severity.MEDIUM {{ background: #ffc107; color: black; }}
        .severity.LOW {{ background: #28a745; color: white; }}
        .finding-details {{
            margin-top: 10px;
            color: #6c757d;
        }}
        .finding-details div {{
            margin: 5px 0;
        }}
        .label {{
            font-weight: bold;
            color: #495057;
        }}
        .no-findings {{
            text-align: center;
            padding: 60px;
            color: #6c757d;
        }}
        .no-findings svg {{
            width: 100px;
            height: 100px;
            margin-bottom: 20px;
            opacity: 0.3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>♊ Zodiac Vulnerability Scanner</h1>
            <div class="subtitle">Professional Web Security Analysis Report</div>
        </div>
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <div class="value">{stats['total_findings']}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats['severity_breakdown'].get('CRITICAL', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats['severity_breakdown'].get('HIGH', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card smallest-value">
                    <div class="value">{len([f for f in self.findings if f.confidence == 'HIGH'])}</div>
                    <div class="label">High Confidence</div>
                </div>
            </div>
            
            <div class="findings">
                <h2>Scan Results</h2>
                <p style="color: #6c757d; margin-bottom: 20px;">
                    Target: <span class="label">{self.metadata.get('target', 'Unknown')}</span> | 
                    Generated: <span class="label">{self.metadata.get('generated_at', 'Unknown')}</span>
                </p>
"""
        
        if not self.findings:
            html += """
                <div class="no-findings">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3>No vulnerabilities detected</h3>
                    <p>Great job! No issues were found during the scan.</p>
                </div>
"""
        else:
            for finding in self.findings:
                evidence = finding.evidence if not sanitize else "<payload-hidden>" if finding.evidence else "N/A"
                html += f"""
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-type">{finding.type}</div>
                        <div class="severity {finding.severity}">{finding.severity}</div>
                    </div>
                    <div class="finding-details">
                        <div><span class="label">Path:</span> {finding.path}</div>
                        {f'<div><span class="label">Parameter:</span> {finding.parameter}</div>' if finding.parameter else ''}
                        <div><span class="label">Confidence:</span> {finding.confidence}</div>
                        <div><span class="label">Evidence:</span> <code>{evidence}</code></div>
                        <div><span class="label">Timestamp:</span> {finding.timestamp}</div>
                    </div>
                </div>
"""
        
        html += """
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

