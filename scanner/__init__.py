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

from scanner.cache import (
    get_cached_result,
    save_to_cache,
    clear_cache,
    get_cache_stats,
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
    "get_cached_result",
    "save_to_cache",
    "clear_cache",
    "get_cache_stats",
]
