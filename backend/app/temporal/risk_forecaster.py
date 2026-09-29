"""
Explainable Temporal Risk Forecaster
Deterministic, rule/statistical projection of a tunnel's risk trajectory —
no black-box model. Every forecast exposes the exact observed factors behind it.
"""
from typing import List

from app.models.temporal_schemas import VPNStateSnapshot, SecurityEvent, RiskForecast

_FACTOR_LABELS = {
    "CRYPTO_DOWNGRADE": "Repeated cryptographic downgrade",
    "DH_DOWNGRADE": "Diffie-Hellman key exchange regression",
    "PFS_DISABLED": "Perfect Forward Secrecy regression",
    "SA_CHURN": "Increasing SA churn",
    "SEQUENCE_ANOMALY": "Increasing IKE renegotiation / anomaly frequency",
    "REPLAY_ANOMALY": "Anti-replay protection violations",
    "IKE_VERSION_CHANGE": "IKE protocol downgrade",
    "BASELINE_VIOLATION": "Repeated baseline policy violations",
    "RISK_SCORE_CHANGE": "Declining aggregate risk score",
}


def forecast(tunnel_id: str, snapshots: List[VPNStateSnapshot], events: List[SecurityEvent]) -> RiskForecast:
    if len(snapshots) < 2:
        return RiskForecast(
            tunnel_id=tunnel_id,
            current_state="INSUFFICIENT_DATA",
            trend="STABLE",
            confidence=0.0,
            disclaimer="At least two historical snapshots are required to project a risk trajectory.",
        )

    scores = [s.overall_score for s in snapshots]
    deltas = [scores[i] - scores[i - 1] for i in range(1, len(scores))]
    declining_steps = sum(1 for d in deltas if d < 0)
    improving_steps = sum(1 for d in deltas if d > 0)

    if declining_steps > improving_steps and declining_steps >= 1:
        trend = "ESCALATING"
    elif improving_steps > declining_steps:
        trend = "IMPROVING"
    else:
        trend = "STABLE"

    dominant_steps = max(declining_steps, improving_steps)
    confidence = round(min(0.95, 0.5 + 0.12 * dominant_steps), 2)

    factor_counts = {}
    for e in events:
        factor_counts[e.event_type] = factor_counts.get(e.event_type, 0) + 1

    if trend == "ESCALATING":
        risk_factors = [
            _FACTOR_LABELS.get(k, k.replace("_", " ").title())
            for k, _ in sorted(factor_counts.items(), key=lambda kv: -kv[1])
        ][:5]
        supporting_events = [e.event_id for e in events if e.event_type in factor_counts][:10]
    else:
        risk_factors = []
        supporting_events = []

    current_state = "DEGRADED" if snapshots[-1].overall_score < 70 else "HEALTHY"

    return RiskForecast(
        tunnel_id=tunnel_id,
        current_state=current_state,
        trend=trend,
        confidence=confidence,
        risk_factors=risk_factors,
        supporting_events=supporting_events,
    )
