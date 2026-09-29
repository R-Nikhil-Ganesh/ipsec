"""
REST API Endpoints for IPsec Sentinel
Conforms to Section 25 (API Design) and Section 27/28 (Demo Lab)
"""
import os
import shutil
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Response, Query, Body
from fastapi.responses import HTMLResponse

from app.models.schemas import (
    AnalysisDetailResponse,
    VPNFingerprint,
    SecurityFinding,
    RiskScoreBreakdown,
    TrafficClassification,
    AnomalyFinding,
    MetadataPrivacyAnalysis,
    ConfigurationDrift,
    RiskPathGraph,
    WhatIfRequest,
    WhatIfResult,
    BaselineConfig,
)
from app.models.temporal_schemas import (
    SecurityTimeline,
    ExposureClock,
    RiskForecast,
    RemediationComparison,
    IncidentReplay,
    ReplayFrame,
)
from app.analyzers.pcap_analyzer import PCAPAnalyzer
from app.security.baseline import get_current_baseline, update_baseline
from app.security.rules_engine import SecurityRulesEngine
from app.security.risk_scorer import RiskScorer
from app.security.risk_graph_builder import RiskGraphBuilder
from app.security.privacy_analyzer import PrivacyAnalyzer
from app.security.drift_detector import DriftDetector
from app.security.whatif_simulator import WhatIfSimulator
from app.ml.traffic_classifier import EncryptedTrafficClassifier
from app.ml.anomaly_detector import AnomalyDetector
from app.reports.report_generator import ReportGenerator
from app.temporal.state_tracker import (
    assign_tunnel,
    get_tunnel_id_for_analysis,
    get_tunnel_timeline_snapshots,
    get_events_for_tunnel,
    refresh_tunnel_events,
)
from app.temporal.event_correlator import correlate_sequences, build_temporal_graph
from app.temporal.exposure_engine import compute_exposure_clock
from app.temporal.risk_forecaster import forecast as forecast_risk
from app.remediation.remediation_planner import build_remediation_plans
from app.remediation.remediation_ranker import rank_plans
from app.database.db import (
    save_analysis,
    get_analysis,
    list_analyses,
    save_baseline_fingerprint,
    get_latest_baseline_fingerprint,
    save_remediation_simulation,
    delete_tunnel_history,
)

router = APIRouter()

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data", "uploads")
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data", "sample_pcaps")
os.makedirs(UPLOAD_DIR, exist_ok=True)

traffic_classifier = EncryptedTrafficClassifier()
anomaly_detector = AnomalyDetector()


def _run_full_analysis(
    file_path: str,
    filename: str,
    dataset_type: str = "PCAP Upload",
    tunnel_id_override: Optional[str] = None,
    override_timestamp: Optional[str] = None,
) -> AnalysisDetailResponse:
    analyzer = PCAPAnalyzer(file_path)
    analysis_res = analyzer.analyze()

    fingerprint: VPNFingerprint = analysis_res["fingerprint"]
    stats = analysis_res["statistics"]
    ike_sum = analysis_res["ike_summary"]
    esp_features = analysis_res["esp_features"]

    # Security Rules & Scoring
    baseline = get_current_baseline()
    rules_engine = SecurityRulesEngine(baseline)
    findings = rules_engine.evaluate(fingerprint)
    risk_score = RiskScorer.calculate_score(findings)

    # ML Encrypted Traffic Classification
    traffic_res = traffic_classifier.classify(esp_features)

    # Anomaly Detection (Isolation Forest + Heuristics)
    anomalies_res = anomaly_detector.detect_anomalies(
        ike_count=stats.ike_packets,
        esp_count=stats.esp_packets,
        flow_features=esp_features,
        exchanges=ike_sum.get("exchanges", [])
    )

    # Metadata Privacy Exposure
    privacy_res = PrivacyAnalyzer.analyze_flow(esp_features)

    # Configuration Drift Detection
    # If the file is 'config_drift_vpn.pcap', or if a baseline fingerprint exists, compare against it
    latest_base_fp_dict = get_latest_baseline_fingerprint()
    if not latest_base_fp_dict and "config_drift" in filename.lower():
        # Use ideal golden baseline for drift demo
        from app.utils.constants import STATE_OBSERVED
        ideal_fp = VPNFingerprint(
            protocol="IPsec",
            ike_version="IKEv2",
            ike_version_status=STATE_OBSERVED,
            mode="Tunnel",
            mode_status=STATE_OBSERVED,
            encryption="AES-256-GCM-16",
            encryption_status=STATE_OBSERVED,
            integrity="AEAD",
            integrity_status=STATE_OBSERVED,
            dh_group="19",
            dh_group_name="DH-Group-19 (ECP-256)",
            dh_group_status=STATE_OBSERVED,
            pfs=True,
            pfs_status=STATE_OBSERVED,
            replay_protection=True,
            replay_protection_status=STATE_OBSERVED,
            sa_lifetime=3600,
            sa_lifetime_status=STATE_OBSERVED
        )
        drift_res = DriftDetector.compare(fingerprint, ideal_fp, "Authorized Enterprise Baseline v2.1")
    elif latest_base_fp_dict:
        base_fp = VPNFingerprint(**latest_base_fp_dict)
        drift_res = DriftDetector.compare(fingerprint, base_fp, "Prior Observed VPN Snapshot")
    else:
        drift_res = DriftDetector.compare(fingerprint, None)

    # Attack & Risk Path Graph
    risk_graph_res = RiskGraphBuilder.build_graph(fingerprint, findings)

    analysis_id = str(uuid.uuid4())[:8]
    now_iso = override_timestamp or datetime.utcnow().isoformat()

    detail = AnalysisDetailResponse(
        id=analysis_id,
        filename=filename,
        analyzed_at=now_iso,
        status="Completed",
        dataset_type=dataset_type,
        fingerprint=fingerprint,
        risk_score=risk_score,
        findings=findings,
        traffic_classification=traffic_res,
        anomalies=anomalies_res,
        metadata_privacy=privacy_res,
        drift=drift_res,
        risk_graph=risk_graph_res,
        packet_stats=stats
    )

    # Persist in SQLite
    save_analysis(detail.model_dump())

    # If this was a strong baseline run, save it as a candidate baseline fingerprint for drift comparisons
    if risk_score.overall_score >= 90:
        save_baseline_fingerprint(analysis_id, f"Baseline-{filename}", fingerprint.model_dump())

    # Temporal Security Twin: group this analysis under a tunnel identity and
    # recompute the tunnel's security-event history from its snapshot series.
    tunnel_id = assign_tunnel(analysis_id, fingerprint, tunnel_id_override)
    refresh_tunnel_events(tunnel_id)

    return detail


@router.post("/analyze/pcap", response_model=AnalysisDetailResponse)
async def analyze_pcap_upload(file: UploadFile = File(...)):
    """
    Primary endpoint for uploading and analyzing a PCAP file.
    """
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a .pcap, .pcapng, or .cap file.")

    safe_name = f"{uuid.uuid4().hex[:8]}_{os.path.basename(file.filename)}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)

    try:
        with open(dest_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        res = _run_full_analysis(dest_path, file.filename, dataset_type="PCAP Upload")
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/analysis/{analysis_id}", response_model=AnalysisDetailResponse)
def get_analysis_detail(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return AnalysisDetailResponse(**data)


@router.get("/analysis/{analysis_id}/fingerprint", response_model=VPNFingerprint)
def get_fingerprint_endpoint(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return VPNFingerprint(**data["fingerprint"])


@router.get("/analysis/{analysis_id}/findings", response_model=List[SecurityFinding])
def get_findings_endpoint(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return [SecurityFinding(**f) for f in data["findings"]]


@router.get("/analysis/{analysis_id}/anomalies", response_model=List[AnomalyFinding])
def get_anomalies_endpoint(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return [AnomalyFinding(**a) for a in data["anomalies"]]


@router.get("/analysis/{analysis_id}/traffic", response_model=TrafficClassification)
def get_traffic_endpoint(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return TrafficClassification(**data["traffic_classification"])


@router.get("/analysis/{analysis_id}/graph", response_model=RiskPathGraph)
def get_graph_endpoint(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return RiskPathGraph(**data["risk_graph"])


@router.get("/analyses")
def list_all_analyses():
    return list_analyses()


@router.post("/simulate", response_model=WhatIfResult)
def simulate_hardening(req: WhatIfRequest, analysis_id: Optional[str] = Query(None)):
    """
    What-If Hardening Simulator endpoint.
    Recalculates posture and explains remediated findings.
    """
    if analysis_id:
        data = get_analysis(analysis_id)
        if not data:
            raise HTTPException(status_code=404, detail="Analysis not found.")
        current_fp = VPNFingerprint(**data["fingerprint"])
    else:
        # Default baseline current fingerprint (Weak crypto configuration)
        current_fp = VPNFingerprint(
            protocol="IPsec",
            ike_version="IKEv1",
            mode="Tunnel",
            encryption="AES-128-CBC",
            integrity="HMAC-SHA1-96",
            dh_group="2",
            dh_group_name="DH-Group-2 (MODP-1024)",
            pfs=False,
            replay_protection=True,
            sa_lifetime=28800
        )

    res = WhatIfSimulator.simulate(current_fp, req)
    return res


# ==========================================
# TEMPORAL SECURITY TWIN ENDPOINTS
# ==========================================

def _resolve_tunnel(analysis_id: str) -> str:
    tunnel_id = get_tunnel_id_for_analysis(analysis_id)
    if not tunnel_id:
        raise HTTPException(status_code=404, detail="Analysis not found or not linked to a tunnel history.")
    return tunnel_id


@router.get("/analysis/{analysis_id}/timeline", response_model=SecurityTimeline)
def get_timeline_endpoint(analysis_id: str):
    """Full historical state series + correlated security events for this tunnel."""
    tunnel_id = _resolve_tunnel(analysis_id)
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    events = get_events_for_tunnel(tunnel_id)
    sequences = correlate_sequences(events)
    is_simulated = any(s.dataset_type == "Controlled laboratory dataset" for s in snapshots)
    return SecurityTimeline(
        tunnel_id=tunnel_id,
        snapshots=snapshots,
        events=events,
        correlated_sequences=sequences,
        is_simulated=is_simulated,
        simulation_label="CONTROLLED LABORATORY SIMULATION" if is_simulated else None,
    )


@router.get("/analysis/{analysis_id}/exposure", response_model=ExposureClock)
def get_exposure_endpoint(analysis_id: str):
    """How long the tunnel has remained in a detected degraded state, if any."""
    tunnel_id = _resolve_tunnel(analysis_id)
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    events = get_events_for_tunnel(tunnel_id)
    return compute_exposure_clock(tunnel_id, snapshots, events)


@router.get("/analysis/{analysis_id}/forecast", response_model=RiskForecast)
def get_forecast_endpoint(analysis_id: str):
    """Explainable, rule-based projection of the tunnel's risk trajectory."""
    tunnel_id = _resolve_tunnel(analysis_id)
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    events = get_events_for_tunnel(tunnel_id)
    return forecast_risk(tunnel_id, snapshots, events)


@router.get("/analysis/{analysis_id}/temporal-graph", response_model=RiskPathGraph)
def get_temporal_graph_endpoint(analysis_id: str):
    """Time-ordered chain of security events, extending the static per-analysis risk graph."""
    tunnel_id = _resolve_tunnel(analysis_id)
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    events = get_events_for_tunnel(tunnel_id)
    return build_temporal_graph(tunnel_id, snapshots, events)


@router.get("/analysis/{analysis_id}/remediation-plans", response_model=RemediationComparison)
def get_remediation_plans_endpoint(analysis_id: str):
    """Automated hardening plans (A/B/C), each scored via the existing What-If simulator."""
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    current_fp = VPNFingerprint(**data["fingerprint"])
    current_findings = [SecurityFinding(**f) for f in data["findings"]]
    current_graph = RiskPathGraph(**data["risk_graph"])

    plans = rank_plans(build_remediation_plans(current_fp, current_findings, current_graph))
    return RemediationComparison(
        analysis_id=analysis_id,
        current_score=data["risk_score"]["overall_score"],
        current_grade=data["risk_score"]["posture_grade"],
        plans=plans,
    )


@router.post("/analysis/{analysis_id}/remediation/simulate", response_model=WhatIfResult)
def simulate_remediation_endpoint(
    analysis_id: str,
    plan_id: Optional[str] = Query(None, description="Apply a plan generated by /remediation-plans"),
    req: Optional[WhatIfRequest] = Body(None, description="Or supply a custom hardening request directly"),
):
    """Applies either a named remediation plan or a custom WhatIfRequest and logs the result."""
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    current_fp = VPNFingerprint(**data["fingerprint"])

    if plan_id:
        current_findings = [SecurityFinding(**f) for f in data["findings"]]
        current_graph = RiskPathGraph(**data["risk_graph"])
        plans = build_remediation_plans(current_fp, current_findings, current_graph)
        plan = next((p for p in plans if p.plan_id == plan_id), None)
        if not plan:
            raise HTTPException(status_code=404, detail=f"Remediation plan '{plan_id}' not found.")
        result = plan.whatif_result
        request_payload = plan.whatif_request.model_dump()
    elif req is not None:
        result = WhatIfSimulator.simulate(current_fp, req)
        request_payload = req.model_dump()
    else:
        raise HTTPException(status_code=400, detail="Provide either a 'plan_id' query param or a WhatIfRequest body.")

    save_remediation_simulation(
        sim_id=uuid.uuid4().hex[:10],
        analysis_id=analysis_id,
        plan_id=plan_id or "custom",
        request_dict=request_payload,
        result_dict=result.model_dump(),
    )
    return result


@router.post("/analysis/{analysis_id}/replay", response_model=IncidentReplay)
def replay_incident_endpoint(analysis_id: str):
    """
    Incident Replay: steps through the tunnel's historical snapshots one at a time,
    recomputing exposure/forecast/temporal-graph as of each point so the frontend can
    animate the security evolution from T0 through the present.
    """
    tunnel_id = _resolve_tunnel(analysis_id)
    snapshots = get_tunnel_timeline_snapshots(tunnel_id)
    all_events = get_events_for_tunnel(tunnel_id)

    frames: List[ReplayFrame] = []
    for i, snap in enumerate(snapshots):
        partial_snapshots = snapshots[: i + 1]
        partial_ids = {s.analysis_id for s in partial_snapshots}
        partial_events = [e for e in all_events if e.analysis_id in partial_ids]

        frames.append(ReplayFrame(
            index=i,
            label=snap.label,
            timestamp=snap.timestamp,
            snapshot=snap,
            events_at_this_point=[e for e in partial_events if e.analysis_id == snap.analysis_id],
            exposure=compute_exposure_clock(tunnel_id, partial_snapshots, partial_events),
            forecast=forecast_risk(tunnel_id, partial_snapshots, partial_events),
            risk_graph=build_temporal_graph(tunnel_id, partial_snapshots, partial_events),
        ))

    is_simulated = any(s.dataset_type == "Controlled laboratory dataset" for s in snapshots)
    return IncidentReplay(
        tunnel_id=tunnel_id,
        frames=frames,
        is_simulated=is_simulated,
        simulation_label="CONTROLLED LABORATORY SIMULATION" if is_simulated else None,
    )


@router.get("/reports/{analysis_id}/executive")
def get_executive_report(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    html = ReportGenerator.generate_executive_html(data)
    return HTMLResponse(content=html)


@router.get("/reports/{analysis_id}/technical")
def get_technical_report(analysis_id: str):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    html = ReportGenerator.generate_technical_html(data)
    return HTMLResponse(content=html)


@router.get("/reports/{analysis_id}/pdf")
def get_pdf_report(analysis_id: str, type: str = Query("technical")):
    data = get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    pdf_bytes = ReportGenerator.generate_pdf_report(data, report_type=type)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=sentinel_{type}_report_{analysis_id}.pdf"}
    )


@router.get("/baseline", response_model=BaselineConfig)
def get_baseline_endpoint():
    return get_current_baseline()


@router.post("/baseline", response_model=BaselineConfig)
def set_baseline_endpoint(cfg: BaselineConfig):
    return update_baseline(cfg)


# ==========================================
# DEMO LAB ENDPOINTS (Section 27 & 28)
# ==========================================

DEMO_SAMPLES = [
    {
        "id": "config-drift",
        "name": "Configuration Drift Demo",
        "pcap": "config_drift_vpn.pcap",
        "tag": "Silent Downgrade",
        "description": "Enterprise tunnel degraded from AES-256-GCM to AES-128-CBC, DH14, PFS disabled. Highlights regression against baseline."
    },
    {
        "id": "weak-crypto",
        "name": "Weak Crypto VPN",
        "pcap": "weak_crypto_vpn.pcap",
        "tag": "High Risk / Critical",
        "description": "Legacy 3DES cipher (Sweet32 vulnerability), HMAC-MD5 collision risk, 1024-bit DH Group 2 (Logjam), PFS disabled."
    },
    {
        "id": "strong-vpn",
        "name": "Strong Modern VPN",
        "pcap": "strong_vpn.pcap",
        "tag": "Hardened / A+ Grade",
        "description": "Modern IKEv2 with AES-256-GCM AEAD cipher, Elliptic Curve DH Group 19 (ECP-256), active PFS, and anti-replay protection."
    },
    {
        "id": "anomalous-vpn",
        "name": "Anomalous Negotiation Storm",
        "pcap": "anomalous_vpn.pcap",
        "tag": "Isolation Forest Outlier",
        "description": "High-frequency IKE handshake storm (20+ handshakes) and deliberate duplicate ESP sequence numbers."
    },
    {
        "id": "legacy-vpn",
        "name": "Legacy DES VPN",
        "pcap": "legacy_vpn.pcap",
        "tag": "Critical Breach Risk",
        "description": "Broken 56-bit single-DES encryption and 768-bit DH Group 1 key exchange over deprecated IKEv1."
    },
    {
        "id": "temporal-evolution",
        "name": "Security Evolution: Silent Escalation",
        "pcap": "(deterministic 5-stage synthetic sequence)",
        "tag": "CONTROLLED LABORATORY SIMULATION",
        "description": "A hardened tunnel silently regresses over time: cipher downgrade, key-exchange regression, PFS loss, and a renegotiation storm. Open the Security Evolution tab afterward to see the timeline, exposure clock, forecast, and remediation plans."
    }
]

# Fixed tunnel identity for the temporal demo scenario so repeated loads replace,
# rather than duplicate, its snapshot history.
TEMPORAL_DEMO_TUNNEL_ID = "tun-demo-temporal-evolution"

# (pcap file, hour offset from "now") — reuses the same 5 pre-generated lab pcaps
# already used by the single-snapshot demos above, just replayed as one time series.
TEMPORAL_DEMO_STAGES = [
    ("strong_vpn.pcap", -4),
    ("config_drift_vpn.pcap", -3),
    ("weak_crypto_vpn.pcap", -2),
    ("anomalous_vpn.pcap", -1),
    ("legacy_vpn.pcap", 0),
]


def _run_temporal_demo_sequence() -> AnalysisDetailResponse:
    # Idempotent: reloading this demo always yields exactly one fresh 5-stage history,
    # so the scenario stays reproducible across repeated demo runs.
    delete_tunnel_history(TEMPORAL_DEMO_TUNNEL_ID)
    base_time = datetime.utcnow()
    last_detail: Optional[AnalysisDetailResponse] = None
    for pcap_name, hour_offset in TEMPORAL_DEMO_STAGES:
        pcap_path = os.path.join(SAMPLE_DIR, pcap_name)
        if not os.path.exists(pcap_path):
            raise HTTPException(status_code=500, detail=f"PCAP file {pcap_name} missing from lab directory.")
        timestamp = (base_time + timedelta(hours=hour_offset)).isoformat()
        last_detail = _run_full_analysis(
            pcap_path,
            pcap_name,
            dataset_type="Controlled laboratory dataset",
            tunnel_id_override=TEMPORAL_DEMO_TUNNEL_ID,
            override_timestamp=timestamp,
        )
    return last_detail


@router.get("/demo/samples")
def list_demo_samples():
    return DEMO_SAMPLES


@router.post("/demo/load/{sample_id}", response_model=AnalysisDetailResponse)
def load_demo_sample(sample_id: str):
    """
    Instantly runs and returns full analysis on one of the pre-packaged lab datasets.
    """
    if sample_id == "temporal-evolution":
        return _run_temporal_demo_sequence()

    target = next((s for s in DEMO_SAMPLES if s["id"] == sample_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Demo sample '{sample_id}' not found.")

    pcap_path = os.path.join(SAMPLE_DIR, target["pcap"])
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=500, detail=f"PCAP file {target['pcap']} missing from lab directory.")

    res = _run_full_analysis(pcap_path, target["pcap"], dataset_type="Controlled laboratory dataset")
    return res
