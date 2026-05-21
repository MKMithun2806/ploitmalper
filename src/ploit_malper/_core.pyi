# Re-export Rust extension functions for type checkers
from ploit_malper._core import (
    deduplicate_records,
    normalize_title_py,
    parse_vulnmalper_json,
    suggest_modules,
    suggest_from_title,
    get_all_known_banners,
    msf_login,
    msf_logout,
    msf_is_authenticated,
    msf_get_workspaces,
    msf_get_hosts,
    msf_check_host_exists,
)

__all__ = [
    "deduplicate_records",
    "normalize_title_py",
    "parse_vulnmalper_json",
    "suggest_modules",
    "suggest_from_title",
    "get_all_known_banners",
    "msf_login",
    "msf_logout",
    "msf_is_authenticated",
    "msf_get_workspaces",
    "msf_get_hosts",
    "msf_check_host_exists",
]
