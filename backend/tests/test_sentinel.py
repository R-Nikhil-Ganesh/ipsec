"""
Comprehensive Automated Test Suite for IPsec Sentinel
Tests parsing, detection, scoring, drift detection, what-if simulator, and API endpoints.
"""
import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analyzers.pcap_analyzer import PCAPAnalyzer
from app.analyzers.ike_parser import IKEParser
from app.analyzers.esp_parser import ESPParser
from app.models.schemas import VPNFingerprint, WhatIfRequest
from app.security.rules_engine import SecurityRulesEngine
from app.security.risk_scorer import RiskScorer
from app.security.baseline import get_current_baseline
from app.security.drift_detector import DriftDetector
from app.security.whatif_simulator import WhatIfSimulator
from app.ml.feature_extractor import FeatureExtractor
from app.ml.traffic_classifier import EncryptedTrafficClassifier
from app.ml.anomaly_detector import AnomalyDetector
from app.utils.constants import STATE_OBSERVED

client = TestClient(app)
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "sample_pcaps")


def test_root_endpoint():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "Operational"


def test_demo_samples_list():
    resp = client.get("/api/demo/samples")
    assert resp.status_code == 200
    samples = resp.json()
    assert len(samples) >= 5
    ids = [s["id"] for s in samples]
    assert "config-drift" in ids
    assert "strong-vpn" in ids
    assert "weak-crypto" in ids


def test_strong_pcap_parsing():
    pcap_path = os.path.join(SAMPLE_DIR, "strong_vpn.pcap")
    assert os.path.exists(pcap_path)
    analyzer = PCAPAnalyzer(pcap_path)
    res = analyzer.analyze()

    fp = res["fingerprint"]
    assert fp.protocol == "IPsec"
    assert fp.ike_version == "IKEv2"
    assert "AES-GCM" in (fp.encryption or "")
    assert fp.dh_group == "19"
    assert fp.replay_protection is True

    # Risk Scoring
    rules = SecurityRulesEngine(get_current_baseline())
    findings = rules.evaluate(fp)
    score = RiskScorer.calculate_score(findings)
    assert score.overall_score >= 95
    assert score.posture_grade in ("A+", "A")


def test_weak_crypto_pcap_parsing():
    pcap_path = os.path.join(SAMPLE_DIR, "weak_crypto_vpn.pcap")
    assert os.path.exists(pcap_path)
    analyzer = PCAPAnalyzer(pcap_path)
    res = analyzer.analyze()

    fp = res["fingerprint"]
    assert fp.ike_version == "IKEv1"
    assert "3DES" in (fp.encryption or "")
    assert fp.dh_group == "2"

    rules = SecurityRulesEngine(get_current_baseline())
    findings = rules.evaluate(fp)
    score = RiskScorer.calculate_score(findings)
    assert score.overall_score < 40  # Grade F
    assert score.posture_grade == "F"

    finding_ids = [f.id for f in findings]
    assert "SEC-CRY-002" in finding_ids  # Sweet32 3DES
    assert "SEC-DH-001" in finding_ids   # Insecure DH Group 2


def test_anomalous_vpn_detection():
    pcap_path = os.path.join(SAMPLE_DIR, "anomalous_vpn.pcap")
    assert os.path.exists(pcap_path)
    analyzer = PCAPAnalyzer(pcap_path)
    res = analyzer.analyze()

    anom_det = AnomalyDetector()
    anomalies = anom_det.detect_anomalies(
        res["statistics"].ike_packets,
        res["statistics"].esp_packets,
        res["esp_features"],
        res["ike_summary"].get("exchanges", [])
    )

    detected = [a for a in anomalies if a.anomaly_detected]
    assert len(detected) >= 1
    anom_types = [a.anomaly_type for a in detected]
    assert any("Handshake" in t or "Sequence" in t for t in anom_types)


def test_configuration_drift_detection():
    baseline_fp = VPNFingerprint(
        protocol="IPsec",
        ike_version="IKEv2",
        encryption="AES-256-GCM-16",
        dh_group="19",
        dh_group_name="DH-Group-19 (ECP-256)",
        pfs=True,
        replay_protection=True,
        sa_lifetime=3600
    )
    downgraded_fp = VPNFingerprint(
        protocol="IPsec",
        ike_version="IKEv2",
        encryption="AES-128-CBC",
        dh_group="14",
        dh_group_name="DH-Group-14 (MODP-2048)",
        pfs=False,
        replay_protection=True,
        sa_lifetime=28800
    )

    drift = DriftDetector.compare(downgraded_fp, baseline_fp)
    assert drift.has_drift is True
    assert len(drift.changes) >= 3

    changed_params = [c.parameter for c in drift.changes]
    assert "Encryption Algorithm" in changed_params
    assert "Diffie-Hellman Group" in changed_params
    assert "Perfect Forward Secrecy (PFS)" in changed_params


def test_whatif_simulator():
    weak_fp = VPNFingerprint(
        protocol="IPsec",
        ike_version="IKEv1",
        mode="Tunnel",
        encryption="3DES-CBC",
        integrity="HMAC-MD5-96",
        dh_group="2",
        pfs=False,
        replay_protection=True,
        sa_lifetime=36000
    )

    req = WhatIfRequest(
        ike_version="IKEv2",
        encryption="AES-256-GCM",
        dh_group="19",
        pfs=True,
        sa_lifetime=3600
    )

    sim = WhatIfSimulator.simulate(weak_fp, req)
    assert sim.projected_score > sim.current_score
    assert sim.score_delta > 50
    assert len(sim.resolved_findings) > 0
    assert "connections" in sim.config_snippet


def test_api_load_demo_sample():
    resp = client.post("/api/demo/load/config-drift")
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "config_drift_vpn.pcap"
    assert "fingerprint" in data
    assert "risk_score" in data
    assert "drift" in data
    assert data["drift"]["has_drift"] is True


def test_report_endpoints():
    load_resp = client.post("/api/demo/load/strong-vpn")
    analysis_id = load_resp.json()["id"]

    # Executive HTML
    resp_exec = client.get(f"/api/reports/{analysis_id}/executive")
    assert resp_exec.status_code == 200
    assert "Executive Assessment" in resp_exec.text

    # Technical HTML
    resp_tech = client.get(f"/api/reports/{analysis_id}/technical")
    assert resp_tech.status_code == 200
    assert "Deep Technical Audit" in resp_tech.text

    # PDF download
    resp_pdf = client.get(f"/api/reports/{analysis_id}/pdf?type=technical")
    assert resp_pdf.status_code == 200
    assert resp_pdf.content.startswith(b"%PDF")
