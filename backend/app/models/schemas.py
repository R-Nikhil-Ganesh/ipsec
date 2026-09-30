"""
Pydantic Schemas for IPsec Sentinel
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PeerInfo(BaseModel):
    initiator_ip: Optional[str] = None
    responder_ip: Optional[str] = None
    initiator_port: Optional[int] = None
    responder_port: Optional[int] = None
    ip_version: str = "IPv4"
    spi_initiator: Optional[str] = None
    spi_responder: Optional[str] = None
    esp_spis: List[str] = Field(default_factory=list)
    # False when no IKE packet was seen, so the IPs/ports above are placeholder defaults
    # rather than values decoded from the capture.
    addresses_observed: bool = True


class VPNFingerprint(BaseModel):
    protocol: str = "IPsec"
    ike_version: Optional[str] = None
    ike_version_status: str = "UNKNOWN"
    mode: Optional[str] = None
    mode_status: str = "UNKNOWN"  # "OBSERVED", "INFERRED", "UNKNOWN"
    encryption: Optional[str] = None
    encryption_status: str = "UNKNOWN"
    integrity: Optional[str] = None
    integrity_status: str = "UNKNOWN"
    authentication: Optional[str] = None
    authentication_status: str = "UNKNOWN"
    dh_group: Optional[str] = None
    dh_group_name: Optional[str] = None
    dh_group_status: str = "UNKNOWN"
    pfs: Optional[bool] = None
    pfs_status: str = "UNKNOWN"
    replay_protection: Optional[bool] = None
    replay_protection_status: str = "UNKNOWN"
    sa_lifetime: Optional[int] = None
    sa_lifetime_status: str = "UNKNOWN"
    nat_traversal: Optional[bool] = None
    nat_traversal_status: str = "UNKNOWN"
    ip_version: Optional[str] = "IPv4"
    confidence: float = 0.0
    evidence: Dict[str, Any] = Field(default_factory=dict)
    peer_info: Optional[PeerInfo] = None


class SecurityFinding(BaseModel):
    id: str
    title: str
    category: str  # Cryptography, Key Exchange, Protocol, Lifetime, Integrity, Replay, Compliance
    severity: str  # Critical, High, Medium, Low, Informational
    score_impact: int  # e.g., -15, -10
    evidence: str
    confidence: float
    why_it_matters: str
    remediation: str
    remediation_patch: Optional[str] = None


class RiskScoreBreakdown(BaseModel):
    overall_score: int
    posture_grade: str
    base_score: int = 100
    total_penalty: int
    category_scores: Dict[str, int]
    findings_count: Dict[str, int]
    score_deductions: List[Dict[str, Any]]


class TrafficClassification(BaseModel):
    traffic_type: str
    confidence: float
    basis: str = "encrypted traffic metadata (packet sizes, burstiness, inter-arrival times)"
    disclaimer: str = "Metadata-based statistical inference. No packet payloads were decrypted."
    packet_count: int
    byte_count: int
    flow_duration_sec: float
    avg_packet_size: float
    packet_size_variance: float
    inter_arrival_mean_ms: float
    class_probabilities: Dict[str, float] = Field(default_factory=dict)


class AnomalyFinding(BaseModel):
    id: str
    anomaly_detected: bool
    anomaly_type: str
    severity: str
    confidence: float
    relevant_features: Dict[str, Any]
    explanation: str
    timestamp_range: Optional[str] = None


class MetadataPrivacyFactor(BaseModel):
    name: str
    value: str
    impact: str  # "High Risk", "Moderate Risk", "Low Risk"
    explanation: str


class MetadataPrivacyAnalysis(BaseModel):
    metadata_exposure_score: int  # 0 to 100
    risk_level: str
    packet_size_variability: str
    timing_regularity: str
    directionality_ratio: float
    burstiness_index: float
    flow_duration: float
    factors: List[MetadataPrivacyFactor] = Field(default_factory=list)
    privacy_recommendation: str


class DriftChange(BaseModel):
    parameter: str
    previous_value: Optional[str]
    current_value: Optional[str]
    severity: str
    security_implication: str


class ConfigurationDrift(BaseModel):
    has_drift: bool
    baseline_id: Optional[str] = None
    baseline_name: Optional[str] = None
    drift_detected_at: Optional[str] = None
    changes: List[DriftChange] = Field(default_factory=list)
    drift_severity: str = "Low"


class RiskGraphNode(BaseModel):
    id: str
    label: str
    category: str
    severity: str
    details: str
    # Optional temporal metadata (populated only by the Temporal Security Twin's
    # /temporal-graph and /replay endpoints; ordinary per-analysis graphs leave these None).
    timestamp: Optional[str] = None
    confidence: Optional[float] = None
    state: Optional[str] = None  # "Observed" | "Potential consequence" | "Requires investigation"
    source_event_id: Optional[str] = None


class RiskGraphEdge(BaseModel):
    source: str
    target: str
    label: str
    confidence: Optional[float] = None
    state: Optional[str] = None


class RiskPathGraph(BaseModel):
    nodes: List[RiskGraphNode]
    edges: List[RiskGraphEdge]


class PacketStatistics(BaseModel):
    total_packets: int
    ipsec_packets: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    nat_t_packets: int
    other_packets: int
    duration_seconds: float
    data_rate_kbps: float
    packet_size_distribution: Dict[str, int]
    timeline_buckets: List[Dict[str, Any]] = Field(default_factory=list)


class AnalysisDetailResponse(BaseModel):
    id: str
    filename: str
    analyzed_at: str
    status: str
    dataset_type: str  # "PCAP Upload" | "Controlled laboratory dataset"
    fingerprint: VPNFingerprint
    risk_score: RiskScoreBreakdown
    findings: List[SecurityFinding]
    traffic_classification: TrafficClassification
    anomalies: List[AnomalyFinding]
    metadata_privacy: MetadataPrivacyAnalysis
    drift: ConfigurationDrift
    risk_graph: RiskPathGraph
    packet_stats: PacketStatistics


class BaselineConfig(BaseModel):
    name: str = "Enterprise Recommended High-Security Baseline"
    preferred_ike_version: str = "IKEv2"
    min_encryption: str = "AES-256-GCM"
    acceptable_encryptions: List[str] = Field(
        default=["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]
    )
    min_dh_group: int = 14
    preferred_dh_groups: List[int] = Field(default=[19, 20, 21, 31])
    require_pfs: bool = True
    require_replay_protection: bool = True
    min_sa_lifetime: int = 1800
    max_sa_lifetime: int = 28800
    require_nat_t: bool = True


class WhatIfRequest(BaseModel):
    ike_version: Optional[str] = None
    encryption: Optional[str] = None
    integrity: Optional[str] = None
    dh_group: Optional[str] = None
    pfs: Optional[bool] = None
    replay_protection: Optional[bool] = None
    sa_lifetime: Optional[int] = None
    mode: Optional[str] = None


class WhatIfResult(BaseModel):
    current_score: int
    projected_score: int
    score_delta: int
    current_grade: str
    projected_grade: str
    resolved_findings: List[SecurityFinding]
    remaining_findings: List[SecurityFinding]
    new_findings: List[SecurityFinding]
    projected_breakdown: RiskScoreBreakdown
    hardening_guidance: List[str]
    config_snippet: str
    disclaimer: str = "Projected security posture based on deterministic rules simulation. Not deployed to live device."
