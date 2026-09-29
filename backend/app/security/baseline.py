"""
Security Baseline Configuration & Policies
Conforming to NIST SP 800-77 Rev. 1, BSI TR-02102-3, and CNSA Suite standards.
"""
from typing import Dict, Any
from app.models.schemas import BaselineConfig

# Default Enterprise High-Security Baseline
_current_baseline = BaselineConfig(
    name="Enterprise Standard Baseline (NIST SP 800-77 Rev. 1)",
    preferred_ike_version="IKEv2",
    min_encryption="AES-256-GCM",
    acceptable_encryptions=[
        "AES-256-GCM",
        "AES-128-GCM",
        "CHACHA20-POLY1305",
        "AES-GCM-16",
        "AES-256-GCM-16"
    ],
    min_dh_group=14,
    preferred_dh_groups=[19, 20, 21, 31],
    require_pfs=True,
    require_replay_protection=True,
    min_sa_lifetime=1800,
    max_sa_lifetime=28800,
    require_nat_t=True
)


def get_current_baseline() -> BaselineConfig:
    global _current_baseline
    return _current_baseline


def update_baseline(new_config: BaselineConfig) -> BaselineConfig:
    global _current_baseline
    _current_baseline = new_config
    return _current_baseline
