#!/usr/bin/env python3
"""
Skill Scanner CLI

A command-line interface for scanning AI skill files for malicious content.

Usage:
    python -m scanner.cli                     # Scan ./skills directory
    python -m scanner.cli -d ./my-skills      # Custom directory
    python -m scanner.cli -f json             # JSON output
    python -m scanner.cli -v                  # Verbose output
    python -m scanner.cli --help              # Show help
"""

import argparse
import json
import sys
from pathlib import Path

# Import from scan module
from scanner.scan import (
    get_skill_files,
    analyze_content,
    load_ignore_list,
    should_skip_file,
    filter_findings,
    load_severity_config,
    apply_severity,
    get_severity_emoji,
    DEFAULT_FAIL_ON,
    DEFAULT_WARN_ON,
)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="skill-scan",
        description="Scan AI skill files for malicious content using Groq AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Scan ./skills directory
  %(prog)s -d ./my-skills         Scan custom directory
  %(prog)s -f json                Output results as JSON
  %(prog)s -f json -o report.json Save JSON report to file
  %(prog)s -v                     Show verbose output
  %(prog)s --no-ignore            Disable ignore list
        """
    )
    
    parser.add_argument(
        "-d", "--dir",
        default="skills",
        metavar="PATH",
        help="Directory containing skill files (default: skills)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write results to file (default: stdout)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including safe files"
    )
    
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Disable ignore list filtering"
    )
    
    parser.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="Path to custom ignore list YAML file"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )
    
    return parser


def scan_directory(
    directory: str,
    output_format: str = "text",
    verbose: bool = False,
    use_ignore_list: bool = True,
    custom_ignore_file: str | None = None
) -> tuple[list, bool, dict]:
    """
    Scan a directory for malicious skill files.
    
    Returns:
        tuple: (results list, has_critical_high bool, severity_summary dict)
    """
    results = []
    all_findings = []
    
    # Load configurations
    severity_config = load_severity_config()
    
    # Load ignore list
    if use_ignore_list:
        if custom_ignore_file:
            # Load custom ignore file
            import yaml
            try:
                with open(custom_ignore_file, encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                ignore_config = {
                    "ignore_patterns": config.get("ignore_patterns", []),
                    "ignore_phrases": [p.lower() for p in config.get("ignore_phrases", [])],
                    "skip_files": config.get("skip_files", [])
                }
            except Exception as e:
                print(f"Warning: Could not load custom ignore file: {e}", file=sys.stderr)
                ignore_config = {"ignore_patterns": [], "ignore_phrases": [], "skip_files": []}
        else:
            ignore_config = load_ignore_list()
    else:
        ignore_config = {"ignore_patterns": [], "ignore_phrases": [], "skip_files": []}
    
    # Find skill files
    skill_files = get_skill_files(directory)
    
    if not skill_files:
        if output_format == "text":
            print(f"No .md files found in {directory}/")
        return [], False, {}
    
    if output_format == "text" and verbose:
        print(f"Found {len(skill_files)} skill file(s) to scan")
        print()
    
    # Scan each file
    for filepath in skill_files:
        file_result = {
            "file": filepath.name,
            "path": str(filepath),
            "status": "safe",
            "findings": [],
            "skipped": False
        }
        
        # Check if file should be skipped
        if should_skip_file(filepath.name, ignore_config):
            file_result["status"] = "skipped"
            file_result["skipped"] = True
            if output_format == "text" and verbose:
                print(f"[SKIP] {filepath.name}")
            results.append(file_result)
            continue
        
        # Read file content
        try:
            content = filepath.read_text(encoding="utf-8")
        except Exception as e:
            file_result["status"] = "error"
            file_result["error"] = str(e)
            has_malicious = True  # Fail closed
            results.append(file_result)
            continue
        
        # Analyze content
        result = analyze_content(content, filepath.name)
        
        # Filter findings if using ignore list
        if result.get("findings") and use_ignore_list:
            original_count = len(result["findings"])
            result["findings"] = filter_findings(result["findings"], ignore_config)
            file_result["filtered_count"] = original_count - len(result["findings"])
            result["is_malicious"] = len(result["findings"]) > 0
        
        # Apply severity to findings
        if result.get("findings"):
            result["findings"] = apply_severity(result["findings"], severity_config)
            all_findings.extend(result["findings"])
        
        # Update file result
        if result.get("error"):
            file_result["status"] = "error"
            file_result["error"] = result["error"]
        elif result.get("is_malicious"):
            file_result["status"] = "malicious"
            file_result["findings"] = result.get("findings", [])
        else:
            file_result["status"] = "safe"
        
        results.append(file_result)
        
        # Print text output
        if output_format == "text":
            if file_result["status"] == "malicious":
                print(f"\n[!] MALICIOUS: {filepath.name}")
                for finding in file_result["findings"]:
                    severity = finding.get("severity", "HIGH")
                    emoji = get_severity_emoji(severity)
                    print(f"    Line {finding.get('line', '?')}: \"{finding.get('text', '')}\"")
                    print(f"    Threat: {finding.get('threat_type', 'Unknown')} | Severity: {emoji} {severity}")
            elif file_result["status"] == "error":
                print(f"[!] ERROR: {filepath.name} - {file_result.get('error')}")
            elif verbose:
                print(f"[OK] {filepath.name}")
    
    # Calculate severity summary
    fail_on = severity_config.get("fail_on", DEFAULT_FAIL_ON)
    warn_on = severity_config.get("warn_on", DEFAULT_WARN_ON)
    
    severity_summary = {
        "CRITICAL": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
        "HIGH": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
        "MEDIUM": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
        "LOW": sum(1 for f in all_findings if f.get("severity") == "LOW"),
    }
    
    has_critical_high = any(f.get("severity") in fail_on for f in all_findings)
    has_errors = any(r["status"] == "error" for r in results)
    
    return results, has_critical_high or has_errors, severity_summary


def main() -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Print header for text format
    if args.format == "text":
        print("=" * 50)
        print("Skill Scanner CLI")
        print("=" * 50)
        print()
    
    # Run scan
    results, should_fail, severity_summary = scan_directory(
        directory=args.dir,
        output_format=args.format,
        verbose=args.verbose,
        use_ignore_list=not args.no_ignore,
        custom_ignore_file=args.ignore_file
    )
    
    # Handle JSON output
    if args.format == "json":
        output_data = {
            "directory": args.dir,
            "has_malicious": should_fail,
            "file_count": len(results),
            "malicious_count": sum(1 for r in results if r["status"] == "malicious"),
            "severity_summary": severity_summary,
            "files": results
        }
        json_output = json.dumps(output_data, indent=2)
        
        if args.output:
            Path(args.output).write_text(json_output, encoding="utf-8")
            print(f"Results written to {args.output}")
        else:
            print(json_output)
    
    # Print summary for text format
    elif args.format == "text":
        print()
        print("=" * 50)
        malicious_count = sum(1 for r in results if r["status"] == "malicious")
        safe_count = sum(1 for r in results if r["status"] == "safe")
        skipped_count = sum(1 for r in results if r["status"] == "skipped")
        
        print(f"Summary: {len(results)} files scanned")
        print(f"  Safe: {safe_count}")
        print(f"  Malicious: {malicious_count}")
        if skipped_count > 0:
            print(f"  Skipped: {skipped_count}")
        
        # Print severity breakdown
        print()
        print("Severity Breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_summary.get(sev, 0)
            if count > 0:
                emoji = get_severity_emoji(sev)
                print(f"  {emoji} {sev}: {count}")
        
        print("=" * 50)
        
        if should_fail:
            print("\n[X] FAILED - CRITICAL/HIGH severity issues detected")
        else:
            print("\n[OK] PASSED - All files are safe")
    
    return 1 if should_fail else 0


if __name__ == "__main__":
    sys.exit(main())
