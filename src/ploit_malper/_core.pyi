# Re-export Rust extension functions for type checkers
from ploit_malper._core import deduplicate_records, normalize_title_py, parse_vulnmalper_json, suggest_modules, get_all_known_banners

__all__ = [
    "deduplicate_records",
    "normalize_title_py",
    "parse_vulnmalper_json",
    "suggest_modules",
    "get_all_known_banners",
]
