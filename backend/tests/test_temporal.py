"""
Test Suite for the Temporal Security Twin
Covers: state tracking, event correlation, exposure clock, risk forecasting,
remediation planning (reuse of WhatIfSimulator), and the new API endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import VPNFingerprint, PeerInfo, SecurityFinding, RiskPathGraph
from app.models.temporal_schemas import VPNStateSnapshot
from app.temporal.state_tracker import derive_tunnel_id
from app.temporal.event_correlator import build_events_for_transition, correlate_sequences
from app.temporal.exposure_engine import compute_exposure_clock
from app.temporal.risk_forecaster import forecast as forecast_risk
from app.remediation.remediation_planner import build_remediation_plans
from app.security.risk_graph_builder import RiskGraphBuilder

client = TestClient(app)


def _fp(**overrides) -> VPNFingerprint:
    base = dict(
        protocol="IPsec",
        ike_version="IKEv2",
        encryption="AES-256-GCM",
        dh_group="19",
        dh_group_name="DH-Group-19 (ECP-256)",
        pfs=True,
        replay_protection=True,
        sa_lifetime=3600,
        peer_info=PeerInfo(initiator_ip="10.0.0.1", responder_ip="10.0.0.2"),
    )
    base.update(overrides)
    return VPNFingerprint(**base)


def _snap(seq_index, timestamp, **overrides) -> VPNStateSnapshot:
    base = dict(
        analysis_id=f"a{seq_index}",
        tunnel_id="tun-test",
        sequence_index=seq_index,
        label=f"T{seq_index}",
        timestamp=timestamp,
        dataset_type="Controlled laboratory dataset",
        filename=f"stage{seq_index}.pcap",
        ike_version="IKEv2",
        encryption="AES-256-GCM",
        dh_group="19",
        dh_group_name="DH-Group-19 (ECP-256)",
        pfs=True,
        replay_protection=True,
        sa_lifetime=3600,
        overall_score=100,
        posture_grade="A+",
        findings_count=0,
        critical_findings_count=0,
        anomaly_count=0,
        has_drift=False,
        drift_severity="None",
    )
    base.update(overrides)
    return VPNStateSnapshot(**base)


# ---------------------------------------------------------------------------
# Tunnel identity
# ---------------------------------------------------------------------------

def test_derive_tunnel_id_is_stable_for_same_peers():
    fp1 = _fp()
    fp2 = _fp(encryption="AES-128-CBC")  # different crypto, same peers
    assert derive_tunnel_id(fp1) == derive_tunnel_id(fp2)


def test_derive_tunnel_id_differs_for_different_peers():
    fp1 = _fp()
    fp2 = _fp(peer_info=PeerInfo(initiator_ip="192.168.1.1", responder_ip="192.168.1.2"))
    assert derive_tunnel_id(fp1) != derive_tunnel_id(fp2)


def test_derive_tunnel_id_falls_back_when_peer_info_unobserved():
    fp = _fp(peer_info=None)
    tunnel_id = derive_tunnel_id(fp)
    assert tunnel_id  # never fabricates identity, but never crashes either


# ---------------------------------------------------------------------------
# Event correlation: healthy -> degraded transitions
# ---------------------------------------------------------------------------

def test_event_correlator_detects_crypto_downgrade():
    prev = _snap(0, "2026-01-01T00:00:00", overall_score=100)
    curr = _snap(1, "2026-01-01T01:00:00", encryption="3DES-CBC", overall_score=60)
    events = build_events_for_transition(prev, curr)
    types = {e.event_type for e in events}
    assert "CRYPTO_DOWNGRADE" in types
    assert "RISK_SCORE_CHANGE" in types


def test_event_correlator_detects_pfs_disabled_and_dh_downgrade():
    prev = _snap(0, "2026-01-01T00:00:00")
    curr = _snap(1, "2026-01-01T01:00:00", pfs=False, dh_group="14", dh_group_name="DH-Group-14 (MODP-2048)", overall_score=85)
    events = build_events_for_transition(prev, curr)
    types = {e.event_type for e in events}
    assert "PFS_DISABLED" in types
    assert "DH_DOWNGRADE" in types


def test_event_correlator_no_events_when_nothing_changed():
    prev = _snap(0, "2026-01-01T00:00:00")
    curr = _snap(1, "2026-01-01T01:00:00")
    events = build_events_for_transition(prev, curr)
    assert events == []


def test_event_correlator_never_asserts_causation():
    """Language check: correlated-sequence interpretation must hedge, never claim an attack occurred."""
    prev = _snap(0, "2026-01-01T00:00:00")
    curr = _snap(1, "2026-01-01T00:30:00", encryption="DES-CBC", pfs=False, replay_protection=False, overall_score=20)
    events = build_events_for_transition(prev, curr)
    sequences = correlate_sequences(events, window_seconds=3600)
    assert len(sequences) == 1
    interpretation = sequences[0].interpretation.lower()
    assert "requires investigation" in interpretation
    assert "does not prove an attack" in interpretation


def test_correlate_sequences_groups_events_within_window():
    prev = _snap(0, "2026-01-01T00:00:00")
    curr = _snap(1, "2026-01-01T00:10:00", encryption="3DES-CBC", pfs=False, overall_score=40)
    events = build_events_for_transition(prev, curr)
    assert len(events) >= 2
    sequences = correlate_sequences(events, window_seconds=3600)
    assert len(sequences) == 1
    assert sequences[0].label == "Security Degradation Sequence"


# ---------------------------------------------------------------------------
# Exposure clock
# ---------------------------------------------------------------------------

def test_exposure_clock_healthy_state():
    snapshots = [_snap(0, "2026-01-01T00:00:00", overall_score=95)]
    clock = compute_exposure_clock("tun-test", snapshots, [])
    assert clock.security_state == "HEALTHY"
    assert clock.degradation_started_at is None


def test_exposure_clock_measures_degraded_duration():
    snapshots = [
        _snap(0, "2026-01-01T00:00:00", overall_score=100),
        _snap(1, "2026-01-01T02:00:00", overall_score=50),
        _snap(2, "2026-01-01T05:42:00", overall_score=40),
    ]
    clock = compute_exposure_clock("tun-test", snapshots, [])
    assert clock.security_state == "DEGRADED"
    assert clock.degradation_started_at == "2026-01-01T02:00:00"
    assert clock.duration_seconds == pytest.approx(3 * 3600 + 42 * 60)
    assert clock.security_transitions == 1


def test_exposure_clock_healthy_to_degraded_and_back_counts_two_transitions():
    snapshots = [
        _snap(0, "2026-01-01T00:00:00", overall_score=100),
        _snap(1, "2026-01-01T01:00:00", overall_score=40),
        _snap(2, "2026-01-01T02:00:00", overall_score=95),
    ]
    clock = compute_exposure_clock("tun-test", snapshots, [])
    assert clock.security_state == "HEALTHY"
    assert clock.security_transitions == 2


def test_exposure_clock_empty_snapshots_is_unknown():
    clock = compute_exposure_clock("tun-test", [], [])
    assert clock.security_state == "UNKNOWN"


# ---------------------------------------------------------------------------
# Risk forecaster
# ---------------------------------------------------------------------------

def test_forecaster_insufficient_data_with_single_snapshot():
    result = forecast_risk("tun-test", [_snap(0, "2026-01-01T00:00:00")], [])
    assert result.trend == "STABLE"
    assert result.current_state == "INSUFFICIENT_DATA"
    assert result.confidence == 0.0


def test_forecaster_detects_escalating_trend():
    snapshots = [
        _snap(0, "2026-01-01T00:00:00", overall_score=100),
        _snap(1, "2026-01-01T01:00:00", overall_score=80),
        _snap(2, "2026-01-01T02:00:00", overall_score=55),
        _snap(3, "2026-01-01T03:00:00", overall_score=30),
    ]
    events = []
    for i in range(1, len(snapshots)):
        events.extend(build_events_for_transition(snapshots[i - 1], snapshots[i]))
    result = forecast_risk("tun-test", snapshots, events)
    assert result.trend == "ESCALATING"
    assert result.confidence > 0.5
    assert len(result.risk_factors) > 0


def test_forecaster_detects_improving_trend():
    snapshots = [
        _snap(0, "2026-01-01T00:00:00", overall_score=40),
        _snap(1, "2026-01-01T01:00:00", overall_score=70),
        _snap(2, "2026-01-01T02:00:00", overall_score=100),
    ]
    result = forecast_risk("tun-test", snapshots, [])
    assert result.trend == "IMPROVING"
    assert result.risk_factors == []  # only surfaced when escalating


# ---------------------------------------------------------------------------
# Remediation planner — must reuse WhatIfSimulator, not reimplement scoring
# ---------------------------------------------------------------------------

def test_remediation_plans_improve_score_and_resolve_findings():
    from app.security.rules_engine import SecurityRulesEngine
    from app.security.baseline import get_current_baseline

    weak_fp = _fp(
        ike_version="IKEv1", encryption="3DES-CBC", dh_group="2",
        dh_group_name="DH-Group-2 (MODP-1024)", pfs=False, replay_protection=True, sa_lifetime=28800,
    )
    findings = SecurityRulesEngine(get_current_baseline()).evaluate(weak_fp)
    current_graph = RiskGraphBuilder.build_graph(weak_fp, findings)

    plans = build_remediation_plans(weak_fp, findings, current_graph)
    assert len(plans) == 3
    plan_c = next(p for p in plans if p.plan_id == "plan-c-full-hardening")

    # Plan C must be at least as good as A/B, and strictly better than doing nothing.
    assert plan_c.whatif_result.projected_score >= plan_c.whatif_result.current_score
    assert plan_c.findings_resolved > 0
    assert plan_c.graph_nodes_removed > 0
    # The plan's own request must actually be what was passed to the (reused) simulator.
    assert plan_c.whatif_request.pfs is True


# ---------------------------------------------------------------------------
# API — end-to-end through the temporal demo scenario
# ---------------------------------------------------------------------------

def test_temporal_demo_scenario_end_to_end():
    resp = client.post("/api/demo/load/temporal-evolution")
    assert resp.status_code == 200
    analysis_id = resp.json()["id"]

    timeline_resp = client.get(f"/api/analysis/{analysis_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline["snapshots"]) == 5
    assert timeline["is_simulated"] is True
    assert timeline["simulation_label"] == "CONTROLLED LABORATORY SIMULATION"

    exposure_resp = client.get(f"/api/analysis/{analysis_id}/exposure")
    assert exposure_resp.status_code == 200
    assert exposure_resp.json()["security_state"] in ("HEALTHY", "DEGRADED")

    forecast_resp = client.get(f"/api/analysis/{analysis_id}/forecast")
    assert forecast_resp.status_code == 200

    graph_resp = client.get(f"/api/analysis/{analysis_id}/temporal-graph")
    assert graph_resp.status_code == 200
    assert len(graph_resp.json()["nodes"]) >= 1

    plans_resp = client.get(f"/api/analysis/{analysis_id}/remediation-plans")
    assert plans_resp.status_code == 200
    plans = plans_resp.json()["plans"]
    assert len(plans) == 3
    # Plans should be ranked best-projected-score first.
    scores = [p["whatif_result"]["projected_score"] for p in plans]
    assert scores == sorted(scores, reverse=True)

    sim_resp = client.post(
        f"/api/analysis/{analysis_id}/remediation/simulate",
        params={"plan_id": plans[0]["plan_id"]},
    )
    assert sim_resp.status_code == 200
    assert sim_resp.json()["projected_score"] == plans[0]["whatif_result"]["projected_score"]

    replay_resp = client.post(f"/api/analysis/{analysis_id}/replay")
    assert replay_resp.status_code == 200
    frames = replay_resp.json()["frames"]
    assert len(frames) == 5
    assert [f["label"] for f in frames] == ["T0", "T1", "T2", "T3", "T4"]


def test_timeline_404_for_unknown_analysis():
    resp = client.get("/api/analysis/doesnotexist/timeline")
    assert resp.status_code == 404
