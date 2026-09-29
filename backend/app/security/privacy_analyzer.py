"""
Encrypted Traffic Metadata Privacy Analyzer
Evaluates passive traffic analysis exposure (packet size distributions, timing periodicity,
burstiness) without decrypting packet payloads.
RFC 4303 Traffic Flow Confidentiality (TFC)
"""
from typing import Dict, Any, List
import numpy as np
from app.models.schemas import MetadataPrivacyAnalysis, MetadataPrivacyFactor


class PrivacyAnalyzer:
    @staticmethod
    def analyze_flow(flow_features: Dict[str, Any]) -> MetadataPrivacyAnalysis:
        pkt_count = flow_features.get("packet_count", 0)
        avg_sz = flow_features.get("avg_packet_size", 0.0)
        std_sz = flow_features.get("std_packet_size", 0.0)
        burst_idx = flow_features.get("burstiness_index", 0.0)
        direction_ratio = flow_features.get("direction_ratio", 0.5)
        duration = flow_features.get("duration_sec", 0.0)
        iat_mean = flow_features.get("inter_arrival_mean_ms", 0.0)
        iat_std = flow_features.get("inter_arrival_std_ms", 0.0)

        factors: List[MetadataPrivacyFactor] = []
        exposure_points = 0

        # 1. Packet Size Variability
        # If std_sz is large, an eavesdropper can easily distinguish distinct application messages / file transfers
        # If std_sz is near 0 (e.g. constant padding or TFC), exposure is minimal
        coef_var_sz = (std_sz / (avg_sz + 1e-6)) if avg_sz > 0 else 0.0
        if coef_var_sz > 0.6:
            size_var = "High"
            exposure_points += 30
            factors.append(MetadataPrivacyFactor(
                name="Packet Length Fingerprinting",
                value=f"High Variability (std={std_sz:.1f}B, CV={coef_var_sz:.2f})",
                impact="High Risk",
                explanation="Wide distribution of encrypted packet sizes allows adversaries to correlate message lengths with known website assets, voice codecs, or document lengths."
            ))
        elif coef_var_sz > 0.2:
            size_var = "Medium"
            exposure_points += 18
            factors.append(MetadataPrivacyFactor(
                name="Packet Length Fingerprinting",
                value=f"Moderate Variability (std={std_sz:.1f}B)",
                impact="Moderate Risk",
                explanation="Moderate size variation reveals general protocol categorization without pinpointing exact payloads."
            ))
        else:
            size_var = "Low (TFC / Uniform Padding)"
            exposure_points += 5
            factors.append(MetadataPrivacyFactor(
                name="Packet Length Masking",
                value="Uniform or Constrained Sizes",
                impact="Low Risk",
                explanation="Low size variance suggests traffic flow padding or uniform MTU packets, frustrating side-channel size analysis."
            ))

        # 2. Timing Regularity
        coef_var_iat = (iat_std / (iat_mean + 1e-6)) if iat_mean > 0 else 0.0
        if 0 < coef_var_iat < 0.25 and pkt_count > 10:
            timing_reg = "Highly Periodic (Isochronous)"
            exposure_points += 28
            factors.append(MetadataPrivacyFactor(
                name="Timing Periodicity (Codec/Beacon)",
                value=f"Isochronous Regularity (mean={iat_mean:.1f}ms, CV={coef_var_iat:.2f})",
                impact="High Risk",
                explanation="Strict periodic intervals strongly leak the presence of VoIP codecs (e.g. 20ms G.711 packets) or automated C2 beacon heartbeats."
            ))
        elif coef_var_iat < 0.7:
            timing_reg = "Moderate Regularity"
            exposure_points += 15
            factors.append(MetadataPrivacyFactor(
                name="Timing Pattern",
                value=f"Semi-regular spacing ({iat_mean:.1f}ms)",
                impact="Moderate Risk",
                explanation="Semi-regular pacing indicates interactive or streamed communication."
            ))
        else:
            timing_reg = "Sporadic / Burst-dominated"
            exposure_points += 10
            factors.append(MetadataPrivacyFactor(
                name="Timing Jitter",
                value="High Jitter / Burst Distribution",
                impact="Low Risk",
                explanation="Irregular packet intervals mask strict application timing signatures."
            ))

        # 3. Directionality Ratio
        # Highly asymmetric (e.g. > 0.85 or < 0.15) clearly denotes client-server download/stream
        if direction_ratio > 0.85 or direction_ratio < 0.15:
            exposure_points += 22
            factors.append(MetadataPrivacyFactor(
                name="Asymmetric Directionality",
                value=f"Direction Ratio: {direction_ratio:.2f}",
                impact="High Risk",
                explanation="Extreme flow asymmetry clearly reveals downstream client-server transfers (video streaming or bulk downloads) to an observer."
            ))
        else:
            exposure_points += 10
            factors.append(MetadataPrivacyFactor(
                name="Balanced Directionality",
                value=f"Direction Ratio: {direction_ratio:.2f}",
                impact="Low Risk",
                explanation="Balanced bidirectional traffic exhibits symmetric communication patterns (e.g. VoIP call, SSH shell, or interactive session)."
            ))

        # 4. Burstiness Index
        if burst_idx > 2.5:
            exposure_points += 20
            factors.append(MetadataPrivacyFactor(
                name="Traffic Burstiness",
                value=f"High Burst Index ({burst_idx:.2f})",
                impact="High Risk",
                explanation="Sudden high-volume bursts followed by idle periods expose user webpage click patterns and chunked media buffering."
            ))
        else:
            exposure_points += 8
            factors.append(MetadataPrivacyFactor(
                name="Traffic Burstiness",
                value=f"Controlled Flow ({burst_idx:.2f})",
                impact="Low Risk",
                explanation="Continuous smooth packet rates hinder burst-correlation attacks."
            ))

        exposure_score = min(100, max(10, exposure_points))

        if exposure_score >= 70:
            risk_level = "High Exposure"
            rec = "Enable RFC 4303 Traffic Flow Confidentiality (TFC) padding to pad ESP packets to fixed sizes and inject dummy packets to mitigate passive traffic side-channels."
        elif exposure_score >= 45:
            risk_level = "Moderate Exposure"
            rec = "Consider applying packet length normalization or randomized jitter if tunneling sensitive voice/interactive command traffic."
        else:
            risk_level = "Low Exposure"
            rec = "Traffic shows high entropy and low side-channel leakage across size and timing dimensions."

        return MetadataPrivacyAnalysis(
            metadata_exposure_score=exposure_score,
            risk_level=risk_level,
            packet_size_variability=size_var,
            timing_regularity=timing_reg,
            directionality_ratio=round(direction_ratio, 2),
            burstiness_index=round(burst_idx, 2),
            flow_duration=round(duration, 2),
            factors=factors,
            privacy_recommendation=rec
        )
