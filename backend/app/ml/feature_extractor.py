"""
Reusable ML Feature Extraction Module
Extracts flow-level and packet-level statistical features from PCAPs and ESP/IKE streams.
"""
from typing import Dict, Any, List
import numpy as np


class FeatureExtractor:
    @staticmethod
    def extract_features(
        packet_lengths: List[int],
        timestamps: List[float],
        directions: List[int],
        ike_count: int = 0,
        esp_count: int = 0,
        ah_count: int = 0,
        natt_count: int = 0,
        ike_version_num: int = 2
    ) -> Dict[str, float]:
        """
        Calculates normalized numeric feature dictionary for machine learning classifiers.
        """
        if not packet_lengths:
            packet_lengths = [0]
        if not timestamps or len(timestamps) < 2:
            timestamps = [0.0, 1.0]

        sz = np.array(packet_lengths, dtype=float)
        ts = np.array(sorted(timestamps), dtype=float)
        iats = np.diff(ts) if len(ts) > 1 else np.array([0.0])

        total_pkts = max(1, len(packet_lengths))
        duration = max(1e-4, float(ts[-1] - ts[0]))
        total_bytes = float(np.sum(sz))

        # Size statistics
        mean_sz = float(np.mean(sz))
        std_sz = float(np.std(sz))
        max_sz = float(np.max(sz))
        min_sz = float(np.min(sz))

        # Timing statistics (in milliseconds)
        mean_iat = float(np.mean(iats) * 1000.0)
        std_iat = float(np.std(iats) * 1000.0)
        max_iat = float(np.max(iats) * 1000.0)
        min_iat = float(np.min(iats) * 1000.0)

        # Directionality
        fwd_count = sum(1 for d in directions if d == 0)
        direction_ratio = float(fwd_count / total_pkts) if total_pkts > 0 else 0.5

        # Burstiness (std IAT / mean IAT)
        burstiness = float(std_iat / (mean_iat + 1e-4)) if mean_iat > 0 else 0.0

        # Size ratios
        small_ratio = float(np.sum(sz <= 128) / total_pkts)
        large_ratio = float(np.sum(sz >= 1200) / total_pkts)

        return {
            "packet_count": float(total_pkts),
            "byte_count": total_bytes,
            "duration_sec": duration,
            "bytes_per_second": float(total_bytes / duration),
            "packets_per_second": float(total_pkts / duration),
            "packet_length_mean": mean_sz,
            "packet_length_std": std_sz,
            "packet_length_max": max_sz,
            "packet_length_min": min_sz,
            "iat_mean_ms": mean_iat,
            "iat_std_ms": std_iat,
            "iat_max_ms": max_iat,
            "iat_min_ms": min_iat,
            "burstiness_index": burstiness,
            "direction_ratio": direction_ratio,
            "small_packet_ratio": small_ratio,
            "large_packet_ratio": large_ratio,
            "ike_presence": 1.0 if ike_count > 0 else 0.0,
            "esp_presence": 1.0 if esp_count > 0 else 0.0,
            "ah_presence": 1.0 if ah_count > 0 else 0.0,
            "natt_presence": 1.0 if natt_count > 0 else 0.0,
            "ike_version_num": float(ike_version_num)
        }
