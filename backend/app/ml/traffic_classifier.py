"""
Encrypted Traffic Metadata Classifier
Classifies encrypted traffic behavior inside ESP tunnels based purely on flow metadata
(packet sizes, inter-arrival times, burstiness, directionality).
RFC 4303 Encrypted Flow Metadata Inference (No payload decryption).
"""
from typing import Dict, Any, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.models.schemas import TrafficClassification


class EncryptedTrafficClassifier:
    def __init__(self):
        self.class_labels = [
            "Video Streaming",
            "VoIP / Real-Time Audio",
            "Web Browsing (HTTPS)",
            "Bulk Transfer / Backup",
            "ICMP / Network Diagnostic"
        ]
        self.feature_names = [
            "packet_length_mean",
            "packet_length_std",
            "iat_mean_ms",
            "iat_std_ms",
            "burstiness_index",
            "direction_ratio",
            "small_packet_ratio",
            "large_packet_ratio"
        ]
        self.model = None
        self._train_classifier()

    def _train_classifier(self):
        """
        Trains a Random Forest classifier on representative metadata vectors for common network profiles.
        """
        # Vector: [mean_len, std_len, mean_iat, std_iat, burstiness, dir_ratio, small_ratio, large_ratio]
        data = [
            # Video Streaming: Large packets, moderate IAT, high downstream asymmetry, high large_ratio
            ([1250, 280, 18.0, 12.0, 0.65, 0.90, 0.05, 0.85], "Video Streaming"),
            ([1320, 210, 15.0, 10.0, 0.60, 0.94, 0.02, 0.92], "Video Streaming"),
            ([1180, 310, 22.0, 16.0, 0.72, 0.88, 0.08, 0.78], "Video Streaming"),

            # VoIP: Small packets (100-220B), ~20ms strictly periodic (std_iat low), symmetric (0.5)
            ([160, 25, 20.0, 2.5, 0.12, 0.50, 0.85, 0.0], "VoIP / Real-Time Audio"),
            ([180, 30, 20.1, 3.0, 0.15, 0.49, 0.80, 0.0], "VoIP / Real-Time Audio"),
            ([140, 20, 19.8, 1.8, 0.09, 0.51, 0.92, 0.0], "VoIP / Real-Time Audio"),

            # Web Browsing: Bursty, moderate size, high size std, high burstiness
            ([680, 520, 65.0, 120.0, 1.85, 0.78, 0.35, 0.40], "Web Browsing (HTTPS)"),
            ([720, 490, 80.0, 150.0, 1.90, 0.82, 0.30, 0.45], "Web Browsing (HTTPS)"),
            ([610, 540, 55.0, 95.0, 1.70, 0.74, 0.40, 0.35], "Web Browsing (HTTPS)"),

            # Bulk Transfer: Max MTU, high data rate, very high large_ratio, continuous
            ([1410, 80, 5.0, 3.0, 0.50, 0.96, 0.02, 0.98], "Bulk Transfer / Backup"),
            ([1420, 60, 4.0, 2.0, 0.45, 0.98, 0.01, 0.99], "Bulk Transfer / Backup"),
            ([1390, 95, 6.0, 4.0, 0.55, 0.95, 0.03, 0.96], "Bulk Transfer / Backup"),

            # ICMP: Constant small size (64-84B), strictly 1000ms intervals, symmetric
            ([84, 2, 1000.0, 5.0, 0.005, 0.50, 1.0, 0.0], "ICMP / Network Diagnostic"),
            ([84, 0, 1000.0, 2.0, 0.002, 0.50, 1.0, 0.0], "ICMP / Network Diagnostic")
        ]

        X = np.array([x[0] for x in data])
        y = np.array([x[1] for x in data])

        self.model = RandomForestClassifier(n_estimators=40, random_state=42)
        self.model.fit(X, y)

    def classify(self, flow_features: Dict[str, Any]) -> TrafficClassification:
        """
        Infers application traffic category using flow features.
        """
        pkt_count = flow_features.get("packet_count", 0)
        byte_count = flow_features.get("byte_count", 0)
        duration = flow_features.get("duration_sec", 0.0)
        avg_sz = flow_features.get("avg_packet_size", 0.0)
        std_sz = flow_features.get("std_packet_size", 0.0)
        iat_mean = flow_features.get("inter_arrival_mean_ms", 0.0)
        iat_std = flow_features.get("inter_arrival_std_ms", 0.0)
        burst_idx = flow_features.get("burstiness_index", 0.0)
        dir_ratio = flow_features.get("direction_ratio", 0.5)

        if pkt_count < 4:
            return TrafficClassification(
                traffic_type="Unknown Encrypted Traffic",
                confidence=0.30,
                basis="encrypted traffic metadata",
                disclaimer="Insufficient ESP packets observed to perform high-confidence flow classification.",
                packet_count=pkt_count,
                byte_count=byte_count,
                flow_duration_sec=round(duration, 2),
                avg_packet_size=round(avg_sz, 1),
                packet_size_variance=round(std_sz ** 2, 1),
                inter_arrival_mean_ms=round(iat_mean, 2),
                class_probabilities={"Unknown": 1.0}
            )

        # Estimate small / large ratio from stats
        small_ratio = 1.0 if avg_sz < 200 else (0.8 if avg_sz < 300 else 0.2)
        large_ratio = 0.9 if avg_sz > 1200 else (0.4 if avg_sz > 700 else 0.05)

        vector = np.array([[
            avg_sz,
            std_sz,
            iat_mean,
            iat_std,
            burst_idx,
            dir_ratio,
            small_ratio,
            large_ratio
        ]])

        pred = self.model.predict(vector)[0]
        probs = self.model.predict_proba(vector)[0]
        classes = self.model.classes_

        prob_dict = {str(c): round(float(p), 2) for c, p in zip(classes, probs)}
        class_idx = list(classes).index(pred)
        confidence = float(probs[class_idx])

        # If confidence is too low, mark as Unknown as required by Section 9
        if confidence < 0.45:
            pred = "Unknown Encrypted Traffic"

        return TrafficClassification(
            traffic_type=pred,
            confidence=round(confidence, 2),
            basis="encrypted traffic metadata (packet sizes, burstiness, inter-arrival times)",
            disclaimer="Metadata-based statistical inference. No packet payloads were decrypted.",
            packet_count=pkt_count,
            byte_count=byte_count,
            flow_duration_sec=round(duration, 2),
            avg_packet_size=round(avg_sz, 1),
            packet_size_variance=round(std_sz ** 2, 1),
            inter_arrival_mean_ms=round(iat_mean, 2),
            class_probabilities=prob_dict
        )
