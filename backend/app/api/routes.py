"""
REST API Endpoints for IPsec Sentinel
Conforms to Section 25 (API Design) and Section 27/28 (Demo Lab)
"""
import os
import shutil
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Response, Query
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
from app.database.db import (
    save_analysis,
    get_analysis,
    list_analyses,
    save_baseline_fingerprint,
    get_latest_baseline_fingerprint,
)

router = APIRouter()

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data", "uploads")
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "data", "sample_pcaps")
os.makedirs(UPLOAD_DIR, exist_ok=True)

traffic_classifier = EncryptedTrafficClassifier()
anomaly_detector = AnomalyDetector()


def _run_full_analysis(file_path: str, filename: str, dataset_type: str = "PCAP Upload") -> AnalysisDetailResponse:
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
    now_iso = datetime.utcnow().isoformat()

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
    }
]


@router.get("/demo/samples")
def list_demo_samples():
    return DEMO_SAMPLES


@router.post("/demo/load/{sample_id}", response_model=AnalysisDetailResponse)
def load_demo_sample(sample_id: str):
    """
    Instantly runs and returns full analysis on one of the pre-packaged lab datasets.
    """
    target = next((s for s in DEMO_SAMPLES if s["id"] == sample_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Demo sample '{sample_id}' not found.")

    pcap_path = os.path.join(SAMPLE_DIR, target["pcap"])
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=500, detail=f"PCAP file {target['pcap']} missing from lab directory.")

    res = _run_full_analysis(pcap_path, target["pcap"], dataset_type="Controlled laboratory dataset")
    return res
