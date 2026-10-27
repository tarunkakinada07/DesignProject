"""Feature schema definition and metadata for Sentinel Extension Detector.

Schema Version: 1.0.0
Persisted alongside model checkpoints to guarantee deterministic feature alignment.
"""

from dataclasses import dataclass
from typing import Any

FEATURE_SCHEMA_VERSION = "1.0.0"

GROUP_A_FEATURES = [
    "manifest_version_num",
    "perm_count_total",
    "perm_count_high_risk",
    "perm_count_medium_risk",
    "has_broad_host_access",
    "has_sensitive_host_patterns",
    "content_script_count",
    "content_script_all_urls",
    "content_script_all_frames",
    "has_background_service_worker",
    "has_background_scripts",
    "has_externally_connectable",
    "web_accessible_resource_count",
    "csp_has_unsafe_eval",
    "csp_has_remote_sources",
    "update_url_is_external",
    "has_native_messaging",
]

GROUP_B_FEATURES = [
    "js_file_count",
    "total_js_bytes",
    "total_js_lines",
    "avg_line_length",
    "max_line_length",
    "call_chrome_webrequest",
    "call_chrome_cookies",
    "call_chrome_tabs",
    "call_chrome_history",
    "call_chrome_storage",
    "call_chrome_scripting",
    "call_chrome_declarativenetrequest",
    "call_chrome_management",
    "call_chrome_proxy",
    "call_chrome_downloads",
    "call_fetch",
    "call_xmlhttprequest",
    "call_websocket",
    "call_sendbeacon",
    "call_eval",
    "call_function_constructor",
    "call_settimeout_string",
    "call_dynamic_script_injection",
    "external_url_count",
    "ip_literal_url_count",
    "shannon_entropy_source",
    "shannon_entropy_strings",
]

GROUP_C_FEATURES = [
    "hex_identifier_count",
    "string_array_rotation_pattern",
    "escape_sequence_ratio",
    "long_base64_blob_count",
    "long_hex_blob_count",
    "atob_btoa_into_eval_or_func",
    "char_code_concatenation_count",
    "is_minified_heuristic",
    "obfuscation_risk_score",
]

GROUP_D_FEATURES = [
    "declared_unused_perm_count",
    "flag_cookies_broadhost_network",
    "flag_webrequest_redirect_broadhost",
    "flag_tabshistory_network",
    "flag_remotescript_eval",
    "flag_allpages_domform_network",
    "remote_code_loading_count",
]

# Complete, deterministic ordered list of all feature keys
ALL_FEATURE_KEYS = GROUP_A_FEATURES + GROUP_B_FEATURES + GROUP_C_FEATURES + GROUP_D_FEATURES


@dataclass(frozen=True)
class FeatureSchema:
    version: str = FEATURE_SCHEMA_VERSION
    feature_names: list[str] = None  # type: ignore

    def __post_init__(self):
        if self.feature_names is None:
            object.__setattr__(self, "feature_names", list(ALL_FEATURE_KEYS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "groups": {
                "group_a_manifest": GROUP_A_FEATURES,
                "group_b_js_static": GROUP_B_FEATURES,
                "group_c_obfuscation": GROUP_C_FEATURES,
                "group_d_behavior": GROUP_D_FEATURES,
            },
        }


DEFAULT_FEATURE_SCHEMA = FeatureSchema()
