"""
Security Event Correlator
Diffs consecutive VPN state snapshots for the same tunnel into typed SecurityEvents,
then groups events that occur close together in time into a CorrelatedSequence.

This module never claims correlation proves an attack — it only flags "potentially
related events" that "require investigation".
"""
import hashlib
from datetime import datetime
from typing import List

from app.models.temporal_schemas import VPNStateSnapshot, SecurityEvent, CorrelatedSequence
from app.models.schemas import RiskPathGraph, RiskGraphNode, RiskGraphEdge
from app.utils.constants import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

# Rough cipher/DH strength ranks used only to decide whether a change is a *downgrade*
# (for event classification) — not a replacement for the rules engine's own scoring.
_CIPHER_RANK = {
    "DES-CBC": 0, "DES-IV64": 0, "3DES-CBC": 1, "AES-128-CBC": 2, "AES-256-CBC": 2,
    "AES-128-GCM": 4, "AES-256-GCM": 5, "CHACHA20-POLY1305": 5,
}


def _cipher_score(name: str) -> int:
    if not name:
        return 3
    upper = name.upper()
    for key, rank in _CIPHER_RANK.items():
        if key in upper:
            return rank
    return 3


def _is_weaker_cipher(prev: str, curr: str) -> bool:
    if not prev or not curr:
        return False
    return _cipher_score(curr) < _cipher_score(prev)


def _is_weaker_dh(prev: str, curr: str) -> bool:
    try:
        return int(curr) < int(prev)
    except (TypeError, ValueError):
        return False


def _event_id(tunnel_id: str, analysis_id: str, event_type: str, salt: int) -> str:
    raw = f"{tunnel_id}:{analysis_id}:{event_type}:{salt}"
    return "evt-" + hashlib.sha1(raw.encode()).hexdigest()[:10]


def build_events_for_transition(prev: VPNStateSnapshot, curr: VPNStateSnapshot) -> List[SecurityEvent]:
    """Diffs two consecutive snapshots of the same tunnel into zero or more SecurityEvents."""
    events: List[SecurityEvent] = []

    def add(event_type: str, severity: str, source: str, prev_v, curr_v, evidence: str, component: str, confidence: float):
        events.append(SecurityEvent(
            event_id=_event_id(curr.tunnel_id, curr.analysis_id, event_type, len(events)),
            tunnel_id=curr.tunnel_id,
            analysis_id=curr.analysis_id,
            timestamp=curr.timestamp,
            event_type=event_type,
            severity=severity,
            source=source,
            previous_value=str(prev_v) if prev_v is not None else None,
            current_value=str(curr_v) if curr_v is not None else None,
            evidence=evidence,
            affected_component=component,
            confidence=confidence,
        ))

    if prev.encryption != curr.encryption:
        weaker = _is_weaker_cipher(prev.encryption, curr.encryption)
        add(
            "CRYPTO_DOWNGRADE" if weaker else "CONFIGURATION_CHANGE",
            SEVERITY_HIGH if weaker else SEVERITY_INFO,
            "fingerprint_diff", prev.encryption, curr.encryption,
            f"Encryption observed as '{curr.encryption}' in {curr.filename} ({curr.label}), "
            f"previously '{prev.encryption}' in {prev.filename} ({prev.label}).",
            "encryption", 0.9,
        )

    if prev.dh_group != curr.dh_group:
        weaker = _is_weaker_dh(prev.dh_group, curr.dh_group)
        add(
            "DH_DOWNGRADE" if weaker else "CONFIGURATION_CHANGE",
            SEVERITY_HIGH if weaker else SEVERITY_INFO,
            "fingerprint_diff", prev.dh_group_name or prev.dh_group, curr.dh_group_name or curr.dh_group,
            f"Diffie-Hellman group changed from {prev.dh_group_name or prev.dh_group} to "
            f"{curr.dh_group_name or curr.dh_group} between {prev.label} and {curr.label}.",
            "dh_group", 0.9,
        )

    if prev.pfs is True and curr.pfs is False:
        add(
            "PFS_DISABLED", SEVERITY_HIGH, "fingerprint_diff", "Enabled", "Disabled",
            f"Perfect Forward Secrecy was active at {prev.label} and disabled by {curr.label}.",
            "pfs", 0.9,
        )

    if prev.ike_version and curr.ike_version and prev.ike_version != curr.ike_version:
        add(
            "IKE_VERSION_CHANGE",
            SEVERITY_MEDIUM if curr.ike_version == "IKEv1" else SEVERITY_INFO,
            "fingerprint_diff", prev.ike_version, curr.ike_version,
            f"IKE version changed from {prev.ike_version} to {curr.ike_version} between {prev.label} and {curr.label}.",
            "ike_version", 0.85,
        )

    if prev.replay_protection is True and curr.replay_protection is False:
        add(
            "REPLAY_ANOMALY", SEVERITY_CRITICAL, "fingerprint_diff", "Protected", "Violated",
            f"Anti-replay protection regressed by {curr.label}; duplicate or out-of-window sequence numbers observed.",
            "replay_protection", 0.85,
        )

    if curr.anomaly_count > 0:
        add(
            "SEQUENCE_ANOMALY" if curr.anomaly_count > prev.anomaly_count else "SA_CHURN",
            SEVERITY_MEDIUM, "anomaly_detector", prev.anomaly_count, curr.anomaly_count,
            f"{curr.anomaly_count} anomaly indicator(s) flagged by the anomaly detector at {curr.label}.",
            "anomaly_detector", 0.7,
        )

    if curr.has_drift and not prev.has_drift:
        add(
            "BASELINE_VIOLATION", SEVERITY_HIGH, "drift_detector", "No drift", curr.drift_severity,
            f"Configuration drift detected against the established baseline at {curr.label}.",
            "drift", 0.8,
        )

    delta = curr.overall_score - prev.overall_score
    if delta != 0:
        add(
            "RISK_SCORE_CHANGE",
            SEVERITY_MEDIUM if delta < 0 else SEVERITY_INFO,
            "risk_scorer", prev.overall_score, curr.overall_score,
            f"Overall risk score moved from {prev.overall_score} to {curr.overall_score} "
            f"({'+' if delta > 0 else ''}{delta}) between {prev.label} and {curr.label}.",
            "risk_score", 1.0,
        )

    return events


def correlate_sequences(events: List[SecurityEvent], window_seconds: int = 4 * 3600) -> List[CorrelatedSequence]:
    """Groups events that occur within `window_seconds` of each other. Never asserts causation."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    sequences: List[CorrelatedSequence] = []
    current_group: List[SecurityEvent] = [sorted_events[0]]

    def close_group(group: List[SecurityEvent]):
        if len(group) < 2:
            return None
        worsening = any(e.severity in (SEVERITY_CRITICAL, SEVERITY_HIGH) for e in group)
        label = "Security Degradation Sequence" if worsening else "Correlated Configuration Sequence"
        seq_id = "seq-" + hashlib.sha1("|".join(e.event_id for e in group).encode()).hexdigest()[:8]
        interpretation = (
            f"{len(group)} potentially related events occurred within the correlation window "
            f"({window_seconds // 3600}h). This flags a possible compound exposure sequence that "
            "requires investigation — it does not prove an attack occurred."
        )
        return CorrelatedSequence(sequence_id=seq_id, label=label, interpretation=interpretation, events=group)

    for evt in sorted_events[1:]:
        last = current_group[-1]
        try:
            t1 = datetime.fromisoformat(last.timestamp)
            t2 = datetime.fromisoformat(evt.timestamp)
            within_window = abs((t2 - t1).total_seconds()) <= window_seconds
        except ValueError:
            within_window = True
        if within_window:
            current_group.append(evt)
        else:
            grouped = close_group(current_group)
            if grouped:
                sequences.append(grouped)
            current_group = [evt]

    grouped = close_group(current_group)
    if grouped:
        sequences.append(grouped)
    return sequences


_TEMPORAL_EVENT_LABELS = {
    "CONFIGURATION_CHANGE": "Configuration Change",
    "CRYPTO_DOWNGRADE": "Cryptographic Downgrade",
    "DH_DOWNGRADE": "Key Exchange Regression",
    "PFS_DISABLED": "Forward Secrecy Regression",
    "IKE_VERSION_CHANGE": "IKE Protocol Change",
    "SA_CHURN": "SA Churn Increase",
    "SEQUENCE_ANOMALY": "Behavioral Anomaly",
    "REPLAY_ANOMALY": "Anti-Replay Violation",
    "RISK_SCORE_CHANGE": "Risk Score Change",
    "BASELINE_VIOLATION": "Baseline Violation (Configuration Drift)",
}


def build_temporal_graph(tunnel_id: str, snapshots: List[VPNStateSnapshot], events: List[SecurityEvent]) -> RiskPathGraph:
    """
    Builds a linear temporal attack/risk path: a chain of the security events observed
    for this tunnel, in time order, each carrying its own timestamp/evidence/confidence.
    Complements (does not replace) the per-analysis RiskGraphBuilder graph.
    """
    nodes: List[RiskGraphNode] = []
    edges: List[RiskGraphEdge] = []

    root_id = "node-tunnel-origin"
    nodes.append(RiskGraphNode(
        id=root_id,
        label=f"Tunnel Observed ({snapshots[0].label if snapshots else 'T0'})",
        category="Architecture",
        severity="Informational",
        details=f"Earliest observed state for tunnel {tunnel_id}.",
        timestamp=snapshots[0].timestamp if snapshots else None,
        confidence=1.0,
        state="Observed",
    ))

    prev_id = root_id
    ordered_events = sorted(events, key=lambda e: e.timestamp)
    for idx, evt in enumerate(ordered_events):
        node_id = f"node-event-{evt.event_id}"
        state = "Observed" if evt.source in ("fingerprint_diff", "drift_detector") else "Potential consequence"
        nodes.append(RiskGraphNode(
            id=node_id,
            label=_TEMPORAL_EVENT_LABELS.get(evt.event_type, evt.event_type.replace("_", " ").title()),
            category="Temporal",
            severity=evt.severity,
            details=evt.evidence,
            timestamp=evt.timestamp,
            confidence=evt.confidence,
            state=state,
            source_event_id=evt.event_id,
        ))
        edges.append(RiskGraphEdge(
            source=prev_id,
            target=node_id,
            label="evolves into",
            confidence=evt.confidence,
            state=state,
        ))
        prev_id = node_id

    # Terminal "requires investigation" node if the sequence trends negative overall.
    if snapshots and len(snapshots) >= 2 and snapshots[-1].overall_score < snapshots[0].overall_score:
        exposure_id = "node-security-exposure-escalation"
        nodes.append(RiskGraphNode(
            id=exposure_id,
            label="Security Exposure Escalation",
            category="Impact",
            severity="High",
            details=(
                f"Risk score declined from {snapshots[0].overall_score} at {snapshots[0].label} to "
                f"{snapshots[-1].overall_score} at {snapshots[-1].label} across the observed history. "
                "Requires investigation — this is a projected exposure trend, not a confirmed compromise."
            ),
            timestamp=snapshots[-1].timestamp,
            confidence=0.75,
            state="Requires investigation",
        ))
        edges.append(RiskGraphEdge(
            source=prev_id, target=exposure_id, label="potentially escalates to",
            confidence=0.75, state="Potential consequence",
        ))

    return RiskPathGraph(nodes=nodes, edges=edges)
