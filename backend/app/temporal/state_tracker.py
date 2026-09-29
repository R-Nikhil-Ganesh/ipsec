"""
Temporal Security Twin — state tracking
Derives a stable tunnel identity from a VPN fingerprint's peer info, groups repeat
analyses of that tunnel together, and rebuilds each analysis row into a VPNStateSnapshot.
Reuses the existing `analyses` table (via app/database/db.py) as the snapshot store —
no duplicate persistence of fingerprint/findings/score data.
"""
import hashlib
from typing import Any, Dict, List, Optional

from app.models.schemas import VPNFingerprint
from app.models.temporal_schemas import VPNStateSnapshot, SecurityEvent
from app.database.db import (
    get_analysis,
    set_tunnel_id,
    get_tunnel_analyses,
    replace_tunnel_events,
    get_tunnel_events,
)
from app.temporal.event_correlator import build_events_for_transition


def derive_tunnel_id(fingerprint: VPNFingerprint) -> str:
    """Stable identity for 'the same tunnel' across repeat analyses, based on peer IPs.

    Real captures rarely change endpoint IPs between re-analyses of the same tunnel;
    when peer info wasn't observed at all, falls back to a shared 'unassigned' bucket
    rather than fabricating an identity.
    """
    peer = fingerprint.peer_info
    if peer and (peer.initiator_ip or peer.responder_ip):
        key = "|".join(sorted([peer.initiator_ip or "", peer.responder_ip or ""]))
    else:
        key = "unassigned-tunnel"
    return "tun-" + hashlib.sha1(key.encode()).hexdigest()[:10]


def assign_tunnel(analysis_id: str, fingerprint: VPNFingerprint, override_tunnel_id: Optional[str] = None) -> str:
    tunnel_id = override_tunnel_id or derive_tunnel_id(fingerprint)
    set_tunnel_id(analysis_id, tunnel_id)
    return tunnel_id


def get_tunnel_id_for_analysis(analysis_id: str) -> Optional[str]:
    data = get_analysis(analysis_id)
    if not data:
        return None
    return data.get("tunnel_id")


def _snapshot_from_row(row: Dict[str, Any], seq_index: int) -> VPNStateSnapshot:
    fp = row["fingerprint"]
    risk = row["risk_score"]
    drift = row["drift"]
    findings = row["findings"]
    anomalies = row["anomalies"]
    return VPNStateSnapshot(
        analysis_id=row["id"],
        tunnel_id=row.get("tunnel_id") or "unassigned-tunnel",
        sequence_index=seq_index,
        label=f"T{seq_index}",
        timestamp=row["analyzed_at"],
        dataset_type=row["dataset_type"],
        filename=row["filename"],
        ike_version=fp.get("ike_version"),
        ike_version_status=fp.get("ike_version_status", "UNKNOWN"),
        encryption=fp.get("encryption"),
        encryption_status=fp.get("encryption_status", "UNKNOWN"),
        dh_group=fp.get("dh_group"),
        dh_group_name=fp.get("dh_group_name"),
        pfs=fp.get("pfs"),
        replay_protection=fp.get("replay_protection"),
        sa_lifetime=fp.get("sa_lifetime"),
        overall_score=risk.get("overall_score", 0),
        posture_grade=risk.get("posture_grade", "F"),
        findings_count=len(findings),
        critical_findings_count=sum(1 for f in findings if f.get("severity") == "Critical"),
        anomaly_count=sum(1 for a in anomalies if a.get("anomaly_detected")),
        has_drift=bool(drift.get("has_drift", False)),
        drift_severity=drift.get("drift_severity", "None"),
    )


def get_tunnel_timeline_snapshots(tunnel_id: str) -> List[VPNStateSnapshot]:
    rows = get_tunnel_analyses(tunnel_id)
    return [_snapshot_from_row(r, i) for i, r in enumerate(rows)]


def get_events_for_tunnel(tunnel_id: str) -> List[SecurityEvent]:
    rows = get_tunnel_events(tunnel_id)
    return [SecurityEvent(**r) for r in rows]


def refresh_tunnel_events(tunnel_id: str) -> List[SecurityEvent]:
    """Recomputes the full event set for a tunnel from its current snapshot history.

    Cheap to recompute in full (a tunnel's history is at most a handful of snapshots
    in this system), so we avoid incremental-update bugs by always rebuilding from scratch.
    """
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    events: List[SecurityEvent] = []
    for i in range(1, len(snapshots)):
        events.extend(build_events_for_transition(snapshots[i - 1], snapshots[i]))
    replace_tunnel_events(tunnel_id, [e.model_dump() for e in events])
    return events
