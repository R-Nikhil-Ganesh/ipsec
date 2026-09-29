"""
Pydantic Schemas for the Temporal Security Twin
Extends the core AnalysisDetailResponse schemas (app/models/schemas.py) with
historical-state, event-correlation, exposure, forecasting, and remediation models.
Nothing here duplicates the core analysis/scoring/drift/graph logic — it wraps it.
"""
from typing import List, Optional
from pydantic import BaseModel, Field

from app.models.schemas import WhatIfRequest, WhatIfResult, RiskPathGraph


class VPNStateSnapshot(BaseModel):
    """One point-in-time observation of a tunnel, derived from a saved analysis row."""
    analysis_id: str
    tunnel_id: str
    sequence_index: int
    label: str  # "T0", "T1", ...
    timestamp: str
    dataset_type: str
    filename: str

    ike_version: Optional[str] = None
    ike_version_status: str = "UNKNOWN"
    encryption: Optional[str] = None
    encryption_status: str = "UNKNOWN"
    dh_group: Optional[str] = None
    dh_group_name: Optional[str] = None
    pfs: Optional[bool] = None
    replay_protection: Optional[bool] = None
    sa_lifetime: Optional[int] = None

    overall_score: int
    posture_grade: str
    findings_count: int
    critical_findings_count: int
    anomaly_count: int
    has_drift: bool
    drift_severity: str


class SecurityEvent(BaseModel):
    event_id: str
    tunnel_id: str
    analysis_id: str
    timestamp: str
    event_type: str  # CONFIGURATION_CHANGE | CRYPTO_DOWNGRADE | DH_DOWNGRADE | PFS_DISABLED |
                      # IKE_VERSION_CHANGE | SA_CHURN | SEQUENCE_ANOMALY | REPLAY_ANOMALY |
                      # RISK_SCORE_CHANGE | BASELINE_VIOLATION
    severity: str
    source: str
    previous_value: Optional[str] = None
    current_value: Optional[str] = None
    evidence: str
    affected_component: str
    confidence: float


class CorrelatedSequence(BaseModel):
    sequence_id: str
    label: str  # "Security Degradation Sequence" | "Correlated Configuration Sequence"
    interpretation: str
    events: List[SecurityEvent] = Field(default_factory=list)


class SecurityTimeline(BaseModel):
    tunnel_id: str
    snapshots: List[VPNStateSnapshot]
    events: List[SecurityEvent]
    correlated_sequences: List[CorrelatedSequence]
    is_simulated: bool = False
    simulation_label: Optional[str] = None


class ExposureClock(BaseModel):
    tunnel_id: str
    security_state: str  # HEALTHY | DEGRADED | UNKNOWN
    degradation_started_at: Optional[str] = None
    reference_time: str
    duration_seconds: float
    duration_human: str
    affected_sas: int
    security_transitions: int
    risk_score_start: Optional[int] = None
    risk_score_current: int
    disclaimer: str = (
        "This measures how long the tunnel has remained in a detected degraded "
        "configuration state. It does not indicate that compromise occurred."
    )


class RiskForecast(BaseModel):
    tunnel_id: str
    current_state: str
    trend: str  # ESCALATING | IMPROVING | STABLE | INSUFFICIENT_DATA
    forecast_window: str = "NEXT_STATE_TRANSITION"
    confidence: float
    risk_factors: List[str] = Field(default_factory=list)
    supporting_events: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "Forecast based on observed telemetry trend across historical snapshots. "
        "This is a projected exposure trajectory, not a certainty of future compromise."
    )


class RemediationChange(BaseModel):
    parameter: str
    from_value: Optional[str] = None
    to_value: Optional[str] = None


class RemediationPlan(BaseModel):
    plan_id: str
    label: str
    problem_summary: str
    changes: List[RemediationChange]
    whatif_request: WhatIfRequest
    whatif_result: WhatIfResult
    findings_resolved: int
    findings_remaining: int
    graph_nodes_removed: int
    graph_edges_removed: int


class RemediationComparison(BaseModel):
    analysis_id: str
    current_score: int
    current_grade: str
    plans: List[RemediationPlan]


class ReplayFrame(BaseModel):
    index: int
    label: str
    timestamp: str
    snapshot: VPNStateSnapshot
    events_at_this_point: List[SecurityEvent]
    exposure: ExposureClock
    forecast: RiskForecast
    risk_graph: RiskPathGraph


class IncidentReplay(BaseModel):
    tunnel_id: str
    frames: List[ReplayFrame]
    is_simulated: bool = False
    simulation_label: Optional[str] = None
