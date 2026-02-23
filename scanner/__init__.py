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
)

__version__ = "1.0.0"
__all__ = [
    "analyze_content",
    "get_skill_files", 
    "load_ignore_list",
    "should_skip_file",
    "filter_findings",
]
