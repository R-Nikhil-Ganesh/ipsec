"""
Isolation Forest Anomaly Detector
Detects statistical anomalies in IPsec negotiation patterns, SA recreations,
and encrypted flow timing deviations.
"""
from typing import Dict, Any, List
import numpy as np
from sklearn.ensemble import IsolationForest
from app.models.schemas import AnomalyFinding
from app.utils.constants import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


class AnomalyDetector:
    def __init__(self):
        # Baseline training data representing normal enterprise IPsec tunnels
        # Features: [ike_ratio, pps, avg_sz, std_sz, iat_mean, burst_idx, dup_seqs, active_spis]
        normal_baseline = [
            [0.05, 30.0, 750, 380, 33.0, 1.2, 0, 2],
            [0.02, 50.0, 820, 340, 20.0, 1.4, 0, 2],
            [0.01, 120.0, 1100, 250, 8.0, 0.8, 0, 2],
            [0.08, 15.0, 520, 420, 66.0, 1.8, 0, 4],
            [0.03, 40.0, 690, 360, 25.0, 1.1, 0, 2],
            [0.04, 25.0, 810, 390, 40.0, 1.3, 0, 2],
            [0.01, 200.0, 1350, 180, 5.0, 0.5, 0, 2]
        ]
        X = np.array(normal_baseline)
        self.iso_forest = IsolationForest(contamination=0.15, random_state=42)
        self.iso_forest.fit(X)

    def detect_anomalies(
        self,
        ike_count: int,
        esp_count: int,
        flow_features: Dict[str, Any],
        exchanges: List[str]
    ) -> List[AnomalyFinding]:
        findings: List[AnomalyFinding] = []
        total_pkts = max(1, ike_count + esp_count)
        ike_ratio = ike_count / total_pkts
        duration = max(1.0, flow_features.get("duration_sec", 1.0))
        pps = total_pkts / duration
        avg_sz = flow_features.get("avg_packet_size", 0.0)
        std_sz = flow_features.get("std_packet_size", 0.0)
        iat_mean = flow_features.get("inter_arrival_mean_ms", 0.0)
        burst_idx = flow_features.get("burstiness_index", 0.0)
        dup_seqs = flow_features.get("replay_violations", 0)
        active_spis = len(flow_features.get("active_spis", []))

        # Vector for Isolation Forest
        feature_vec = np.array([[
            ike_ratio,
            pps,
            avg_sz,
            std_sz,
            iat_mean,
            burst_idx,
            dup_seqs,
            active_spis
        ]])

        score = float(self.iso_forest.score_samples(feature_vec)[0])
        is_outlier = bool(self.iso_forest.predict(feature_vec)[0] == -1)

        # 1. Check for IKE renegotiation storms / handshake floods
        if ike_count > 15 and (ike_ratio > 0.4 or pps > 50.0):
            findings.append(AnomalyFinding(
                id="ANOM-IKE-001",
                anomaly_detected=True,
                anomaly_type="Repeated Handshake / Negotiation Storm",
                severity=SEVERITY_HIGH,
                confidence=0.91,
                relevant_features={
                    "ike_packet_count": ike_count,
                    "ike_traffic_ratio": round(ike_ratio, 2),
                    "packets_per_sec": round(pps, 1)
                },
                explanation="Potentially anomalous behavior requiring investigation: Unusually high frequency of IKE handshake exchanges observed relative to active data flow. This pattern may indicate misconfigured authentication retries, gateway flapping, or deliberate negotiation state exhaustion attempts."
            ))

        # 2. Check for duplicate sequence numbers / replay anomalies
        if dup_seqs > 0:
            findings.append(AnomalyFinding(
                id="ANOM-ESP-001",
                anomaly_detected=True,
                anomaly_type="ESP Sequence Number Duplication",
                severity=SEVERITY_HIGH,
                confidence=0.94,
                relevant_features={
                    "duplicate_sequence_count": dup_seqs,
                    "active_spis": active_spis
                },
                explanation="Potentially anomalous behavior requiring investigation: Duplicate ESP 32-bit sequence numbers detected within the same security association. This deviation may indicate network packet looping, routing duplication, or an in-flight replay attempt."
            ))

        # 3. Check for rapid SA churn / excessive active SPIs
        if active_spis > 6:
            findings.append(AnomalyFinding(
                id="ANOM-SA-001",
                anomaly_detected=True,
                anomaly_type="Abnormal Security Association Churn",
                severity=SEVERITY_MEDIUM,
                confidence=0.88,
                relevant_features={
                    "distinct_esp_spis": active_spis,
                    "duration_sec": round(duration, 1)
                },
                explanation="Potentially anomalous behavior requiring investigation: Rapid creation of multiple active SPI pairs within a condensed timeframe. Normal tunnels maintain 2 concurrent SPIs during standard rekeying; excessive distinct SPIs suggest rapid teardowns or connection instability."
            ))

        # 4. Check for extreme traffic burstiness
        if burst_idx > 3.0 and pps > 80.0:
            findings.append(AnomalyFinding(
                id="ANOM-TRF-001",
                anomaly_detected=True,
                anomaly_type="Abnormal Traffic Burst Spike",
                severity=SEVERITY_LOW,
                confidence=0.82,
                relevant_features={
                    "burstiness_index": round(burst_idx, 2),
                    "inter_arrival_mean_ms": round(iat_mean, 2)
                },
                explanation="Potentially anomalous behavior requiring investigation: Statistically significant packet arrival burstiness deviation from steady-state profile."
            ))

        # 5. Isolation Forest General Outlier Detection
        if is_outlier and not findings:
            findings.append(AnomalyFinding(
                id="ANOM-ISO-001",
                anomaly_detected=True,
                anomaly_type="Multi-Dimensional Statistical Anomaly",
                severity=SEVERITY_LOW,
                confidence=round(min(0.95, max(0.60, abs(score) * 1.5)), 2),
                relevant_features={
                    "isolation_forest_score": round(score, 3),
                    "pps": round(pps, 1),
                    "avg_packet_size": round(avg_sz, 1),
                    "ike_ratio": round(ike_ratio, 2)
                },
                explanation="Potentially anomalous behavior requiring investigation: Flow feature vector significantly deviates from the normal enterprise baseline envelope in multi-dimensional space."
            ))

        if not findings:
            findings.append(AnomalyFinding(
                id="ANOM-NORM-001",
                anomaly_detected=False,
                anomaly_type="Normal Baseline Behavior",
                severity=SEVERITY_INFO,
                confidence=0.92,
                relevant_features={
                    "ike_count": ike_count,
                    "esp_count": esp_count,
                    "active_spis": active_spis,
                    "isolation_forest_score": round(score, 3)
                },
                explanation="Observed negotiation and data plane parameters operate within expected operational baselines."
            ))

        return findings
