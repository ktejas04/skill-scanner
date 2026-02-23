"""
PR Comment Generator

Formats scan results as a GitHub PR comment.
"""

import json
import sys
from pathlib import Path


def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵"
    }.get(severity.upper(), "⚪")


def format_pr_comment(results: dict) -> str:
    """
    Format scan results as a GitHub PR comment.
    
    Args:
        results: Scan results dictionary from JSON output
        
    Returns:
        Markdown formatted comment string
    """
    has_malicious = results.get("has_malicious", False)
    file_count = results.get("file_count", 0)
    malicious_count = results.get("malicious_count", 0)
    severity_summary = results.get("severity_summary", {})
    files = results.get("files", [])
    
    # Header with status
    if has_malicious:
        header = "## 🚨 Security Scan Failed\n\n"
        status_badge = "❌ **Status: FAILED**"
    else:
        header = "## ✅ Security Scan Passed\n\n"
        status_badge = "✅ **Status: PASSED**"
    
    # Summary section
    summary = f"""### Summary

{status_badge}

| Metric | Count |
|--------|-------|
| Files Scanned | {file_count} |
| Safe | {sum(1 for f in files if f.get('status') == 'safe')} |
| Malicious | {malicious_count} |
| Skipped | {sum(1 for f in files if f.get('status') == 'skipped')} |

"""
    
    # Severity breakdown (only if there are findings)
    severity_section = ""
    if any(severity_summary.get(s, 0) > 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        severity_section = "### Severity Breakdown\n\n"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_summary.get(sev, 0)
            if count > 0:
                emoji = get_severity_emoji(sev)
                severity_section += f"- {emoji} **{sev}**: {count}\n"
        severity_section += "\n"
    
    # Detailed findings
    findings_section = ""
    malicious_files = [f for f in files if f.get("status") == "malicious"]
    
    if malicious_files:
        findings_section = "### Findings\n\n"
        for file_info in malicious_files:
            filename = file_info.get("file", "Unknown")
            findings = file_info.get("findings", [])
            
            findings_section += f"<details>\n<summary>📄 <b>{filename}</b> ({len(findings)} issues)</summary>\n\n"
            findings_section += "| Line | Issue | Threat Type | Severity |\n"
            findings_section += "|------|-------|-------------|----------|\n"
            
            for finding in findings:
                line = finding.get("line", "?")
                text = finding.get("text", "")[:50]  # Truncate long text
                if len(finding.get("text", "")) > 50:
                    text += "..."
                threat = finding.get("threat_type", "Unknown")
                severity = finding.get("severity", "HIGH")
                emoji = get_severity_emoji(severity)
                
                # Escape pipe characters in text
                text = text.replace("|", "\\|")
                
                findings_section += f"| {line} | {text} | {threat} | {emoji} {severity} |\n"
            
            findings_section += "\n</details>\n\n"
    
    # Footer
    footer = "---\n*🤖 Automated security scan by [Skill Scanner](https://github.com/ktejas04/skill-scanner)*"
    
    return header + summary + severity_section + findings_section + footer


def main():
    """CLI entry point for PR comment generation."""
    if len(sys.argv) < 2:
        print("Usage: python pr_comment.py <results.json>", file=sys.stderr)
        sys.exit(1)
    
    json_path = Path(sys.argv[1])
    
    if not json_path.exists():
        print(f"Error: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(json_path, encoding="utf-8") as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    comment = format_pr_comment(results)
    print(comment)


if __name__ == "__main__":
    main()
