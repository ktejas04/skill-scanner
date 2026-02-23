"""
Cache module for scan results.

Caches AI analysis results by file content hash to avoid
re-scanning unchanged files.
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime


# Default cache directory
CACHE_DIR = Path(".scan-cache")

# Runtime stats tracking
_cache_hits = 0
_cache_misses = 0


def reset_cache_stats():
    """Reset runtime cache hit/miss counters."""
    global _cache_hits, _cache_misses
    _cache_hits = 0
    _cache_misses = 0


def record_cache_hit():
    """Record a cache hit."""
    global _cache_hits
    _cache_hits += 1


def record_cache_miss():
    """Record a cache miss."""
    global _cache_misses
    _cache_misses += 1


def get_content_hash(content: str) -> str:
    """Generate SHA256 hash of file content (first 16 chars)."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def get_cache_path(content_hash: str, cache_dir: Path = CACHE_DIR) -> Path:
    """Get the cache file path for a content hash."""
    return cache_dir / f"{content_hash}.json"


def get_cached_result(content: str, cache_dir: Path = CACHE_DIR) -> dict | None:
    """
    Check if we have a cached result for this content.
    
    Args:
        content: File content to look up
        cache_dir: Directory containing cache files
        
    Returns:
        Cached result dict if found, None otherwise
    """
    content_hash = get_content_hash(content)
    cache_file = get_cache_path(content_hash, cache_dir)
    
    if not cache_file.exists():
        return None
    
    try:
        with open(cache_file, encoding="utf-8") as f:
            cached = json.load(f)
        
        # Verify the hash matches (integrity check)
        if cached.get("content_hash") != content_hash:
            return None
        
        return cached.get("result")
    except (json.JSONDecodeError, IOError):
        return None


def save_to_cache(
    content: str, 
    result: dict, 
    filename: str = "",
    cache_dir: Path = CACHE_DIR
) -> bool:
    """
    Save scan result to cache.
    
    Args:
        content: File content that was scanned
        result: Scan result to cache
        filename: Original filename (for reference)
        cache_dir: Directory to store cache files
        
    Returns:
        True if saved successfully, False otherwise
    """
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        content_hash = get_content_hash(content)
        cache_file = get_cache_path(content_hash, cache_dir)
        
        cache_entry = {
            "content_hash": content_hash,
            "filename": filename,
            "cached_at": datetime.utcnow().isoformat(),
            "result": result
        }
        
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_entry, f, indent=2)
        
        return True
    except IOError:
        return False


def clear_cache(cache_dir: Path = CACHE_DIR) -> int:
    """
    Clear all cached results.
    
    Returns:
        Number of cache files deleted
    """
    if not cache_dir.exists():
        return 0
    
    count = 0
    for cache_file in cache_dir.glob("*.json"):
        try:
            cache_file.unlink()
            count += 1
        except IOError:
            pass
    
    return count


def get_cache_stats(cache_dir: Path = CACHE_DIR) -> dict:
    """
    Get cache statistics.
    
    Returns:
        Dict with cache stats (hits, misses, file_count, total_size_bytes)
    """
    if not cache_dir.exists():
        return {"hits": _cache_hits, "misses": _cache_misses, "file_count": 0, "total_size_bytes": 0}
    
    files = list(cache_dir.glob("*.json"))
    total_size = sum(f.stat().st_size for f in files)
    
    return {
        "hits": _cache_hits,
        "misses": _cache_misses,
        "file_count": len(files),
        "total_size_bytes": total_size
    }
