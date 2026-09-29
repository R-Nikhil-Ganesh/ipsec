"""
AI Protocol Classifier
Modular feature-based ML model for classifying IPsec vs non-IPsec, Tunnel vs Transport,
and handshake versions based on header and flow characteristics.
"""
from typing import Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier


class ProtocolClassifier:
    def __init__(self):
        # Features used for classification
        self.feature_names = [
            "packet_length_mean",
            "packet_length_std",
            "packet_length_max",
            "iat_mean_ms",
            "burstiness_index",
            "direction_ratio",
            "small_packet_ratio",
            "large_packet_ratio",
            "ike_presence",
            "esp_presence",
            "natt_presence"
        ]
        self.model_mode = None
        self._init_models()

    def _init_models(self):
        """
        Initializes and pre-trains a RandomForestClassifier on synthetic baseline distributions
        of Tunnel Mode vs Transport Mode.
        """
        # X: [packet_length_mean, packet_length_std, packet_length_max, iat_mean_ms, burstiness, direction_ratio, small_ratio, large_ratio, ike_presence, esp_presence, natt_presence]
        # Tunnel mode synthetic vectors (diverse payloads, MTU clamping ~1420B, high size std, high natt)
        tunnel_samples = [
            [850, 420, 1420, 45, 1.8, 0.65, 0.2, 0.45, 1, 1, 1],
            [920, 380, 1440, 30, 2.1, 0.70, 0.15, 0.50, 1, 1, 1],
            [780, 450, 1400, 60, 1.5, 0.55, 0.25, 0.40, 1, 1, 0],
            [1100, 300, 1420, 15, 2.8, 0.85, 0.1, 0.70, 1, 1, 1],
            [650, 480, 1380, 80, 1.2, 0.60, 0.3, 0.35, 1, 1, 0],
            [890, 410, 1440, 25, 2.4, 0.75, 0.18, 0.48, 1, 1, 1]
        ]
        # Transport mode synthetic vectors (end-to-end host traffic, lower MTU clipping, lower variance or fixed protocol)
        transport_samples = [
            [350, 120, 800, 20, 0.8, 0.50, 0.4, 0.05, 0, 1, 0],
            [280, 90, 650, 15, 0.7, 0.52, 0.5, 0.0, 0, 1, 0],
            [420, 150, 900, 35, 1.0, 0.48, 0.3, 0.1, 1, 1, 0],
            [310, 80, 580, 22, 0.6, 0.51, 0.45, 0.0, 0, 1, 0],
            [480, 190, 950, 40, 1.1, 0.50, 0.25, 0.15, 1, 1, 0]
        ]

        X = np.array(tunnel_samples + transport_samples)
        y = np.array(["Tunnel"] * len(tunnel_samples) + ["Transport"] * len(transport_samples))

        self.model_mode = RandomForestClassifier(n_estimators=30, random_state=42)
        self.model_mode.fit(X, y)

    def classify_mode(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Classifies Tunnel vs Transport mode using the trained RandomForest model.
        Returns prediction, confidence, and features used.
        """
        vector = np.array([[features.get(f, 0.0) for f in self.feature_names]])
        pred = self.model_mode.predict(vector)[0]
        probs = self.model_mode.predict_proba(vector)[0]
        classes = self.model_mode.classes_

        class_idx = list(classes).index(pred)
        confidence = float(probs[class_idx])

        return {
            "prediction": pred,
            "confidence": round(confidence, 2),
            "features_used": {f: features.get(f, 0.0) for f in self.feature_names}
        }
