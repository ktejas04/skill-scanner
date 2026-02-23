"""
Skill Scanner Package

AI-powered malicious content detection for skill files.
"""

from scanner.scan import (
    analyze_content,
    get_skill_files,
    load_ignore_list,
    should_skip_file,
    filter_findings,
    load_severity_config,
    apply_severity,
    get_severity_emoji,
)

__version__ = "1.0.0"
__all__ = [
    "analyze_content",
    "get_skill_files", 
    "load_ignore_list",
    "should_skip_file",
    "filter_findings",
    "load_severity_config",
    "apply_severity",
    "get_severity_emoji",
]
