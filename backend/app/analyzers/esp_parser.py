"""
ESP (Encapsulating Security Payload) and Traffic Flow Analyzer
RFC 4303 - IP Encapsulating Security Payload (ESP)
RFC 3948 - UDP Encapsulation of IPsec ESP Packets
"""
from typing import Dict, Any, List, Optional, Tuple
import struct
import numpy as np
from app.utils.constants import STATE_OBSERVED, STATE_INFERRED, STATE_UNKNOWN


class ESPParser:
    def __init__(self):
        self.esp_packet_count: int = 0
        self.ah_packet_count: int = 0
        self.observed_spis: Dict[str, Dict[str, Any]] = {}  # spi_hex -> {count, seq_nums, first_seen, last_seen}
        self.packet_sizes: List[int] = []
        self.timestamps: List[float] = []
        self.directions: List[int] = []  # 0 for forward (init->resp), 1 for reverse
        self.primary_endpoints: Tuple[Optional[str], Optional[str]] = (None, None)
        self.replay_violations_detected: int = 0
        self.total_bytes: int = 0
        self.udp_encapsulated_count: int = 0

    def parse_packet(
        self,
        packet_idx: int,
        timestamp: float,
        ip_src: str,
        ip_dst: str,
        raw_esp_payload: bytes,
        is_udp_encap: bool = False
    ) -> Dict[str, Any]:
        """
        Parses an ESP packet header:
        - 4 Bytes: SPI (Security Parameter Index)
        - 4 Bytes: Sequence Number
        - Variable: Payload Data + IV
        """
        if len(raw_esp_payload) < 8:
            return {"parsed": False, "reason": "Payload smaller than ESP header (8 bytes)"}

        self.esp_packet_count += 1
        if is_udp_encap:
            self.udp_encapsulated_count += 1

        spi_val, seq_num = struct.unpack("!II", raw_esp_payload[:8])
        spi_hex = f"0x{spi_val:08x}"
        pkt_len = len(raw_esp_payload)
        self.packet_sizes.append(pkt_len)
        self.timestamps.append(timestamp)
        self.total_bytes += pkt_len

        # Direction tracking
        if self.primary_endpoints == (None, None):
            self.primary_endpoints = (ip_src, ip_dst)
            self.directions.append(0)
        else:
            if ip_src == self.primary_endpoints[0] and ip_dst == self.primary_endpoints[1]:
                self.directions.append(0)
            else:
                self.directions.append(1)

        # SPI & Sequence Number tracking
        if spi_hex not in self.observed_spis:
            self.observed_spis[spi_hex] = {
                "spi": spi_hex,
                "packet_count": 1,
                "src_ip": ip_src,
                "dst_ip": ip_dst,
                "min_seq": seq_num,
                "max_seq": seq_num,
                "seq_numbers": [seq_num],
                "duplicate_seq_count": 0,
                "is_monotonic": True
            }
        else:
            entry = self.observed_spis[spi_hex]
            entry["packet_count"] += 1
            if seq_num in entry["seq_numbers"]:
                entry["duplicate_seq_count"] += 1
                self.replay_violations_detected += 1
            if seq_num < entry["max_seq"]:
                entry["is_monotonic"] = False
            else:
                entry["max_seq"] = seq_num
            entry["seq_numbers"].append(seq_num)

        return {
            "packet_index": packet_idx,
            "spi": spi_hex,
            "seq_num": seq_num,
            "length": pkt_len,
            "is_udp_encap": is_udp_encap
        }

    def infer_tunnel_vs_transport(self, has_ts_subnet: Optional[bool] = None) -> Tuple[str, str, float, str]:
        """
        Infers whether the VPN traffic operates in Tunnel Mode or Transport Mode.
        Returns (mode, status, confidence, evidence_reason).
        """
        # If IKE negotiated subnet-to-subnet traffic selectors (e.g. 10.0.0.0/24 to 192.168.1.0/24),
        # or non-host masks, it is OBSERVED Tunnel mode.
        if has_ts_subnet is True:
            return ("Tunnel", STATE_OBSERVED, 0.98, "Observed IKE Traffic Selector subnets spanning routed networks")

        if self.esp_packet_count == 0:
            return ("Unknown", STATE_UNKNOWN, 0.0, "No ESP packets observed to analyze mode")

        # Statistical header heuristic on packet lengths and MTU clamping
        # In tunnel mode, outer IP header (20B) + ESP (8B header + IV + pad + ICV ~36-40B) + inner IP (20B)
        # leads to characteristic packet length distributions (e.g. max ~1420-1440 instead of 1500)
        sizes = np.array(self.packet_sizes)
        max_size = int(np.max(sizes)) if len(sizes) > 0 else 0
        mean_size = float(np.mean(sizes)) if len(sizes) > 0 else 0

        # Gateway-to-gateway behavior check:
        # Tunnel mode encapsulates packets of varying inner protocols, producing diverse payload lengths
        size_std = float(np.std(sizes)) if len(sizes) > 1 else 0.0

        if self.udp_encapsulated_count > 0:
            # UDP 4500 encapsulation is overwhelmingly used in site-to-site / remote-access tunnel setups across NAT
            return ("Tunnel", STATE_INFERRED, 0.91, f"NAT-T UDP/4500 encapsulation observed with size variability (std={size_std:.1f})")

        if max_size > 1400:
            return ("Tunnel", STATE_INFERRED, 0.85, f"Observed standard tunnel MTU packet profiles (max={max_size}B, mean={mean_size:.1f}B)")

        return ("Transport", STATE_INFERRED, 0.72, f"Packet size profile consistent with host-to-host transport encapsulation")

    def infer_replay_protection(self) -> Tuple[Optional[bool], str, float, str]:
        """
        Evaluates replay protection status based on observed sequence numbers.
        Returns (enabled, status, confidence, evidence).
        """
        if self.esp_packet_count < 3:
            return (None, STATE_UNKNOWN, 0.0, "Insufficient ESP packet count to evaluate sequence numbers")

        if self.replay_violations_detected > 0:
            return (
                False,
                STATE_OBSERVED,
                0.95,
                f"Detected {self.replay_violations_detected} duplicate sequence numbers across ESP flows (Replay attack or disabled window)"
            )

        # Sequence numbers are strictly incrementing and non-repeating
        all_monotonic = all(e.get("is_monotonic", False) for e in self.observed_spis.values())
        if all_monotonic:
            return (
                True,
                STATE_OBSERVED,
                0.94,
                f"Monotonically increasing 32-bit sequence numbers without repetition across {self.esp_packet_count} packets"
            )

        return (
            True,
            STATE_INFERRED,
            0.80,
            f"No duplicate sequence numbers observed in sliding window ({self.esp_packet_count} packets)"
        )

    def compute_flow_features(self) -> Dict[str, Any]:
        """Computes statistical features over ESP flow for ML and privacy analysis."""
        if not self.timestamps or len(self.timestamps) < 2:
            duration = 0.0
            iats = []
        else:
            duration = max(self.timestamps) - min(self.timestamps)
            sorted_ts = sorted(self.timestamps)
            iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

        sizes = np.array(self.packet_sizes) if self.packet_sizes else np.array([0])
        iat_arr = np.array(iats) if iats else np.array([0.0])

        fwd_count = sum(1 for d in self.directions if d == 0)
        rev_count = sum(1 for d in self.directions if d == 1)
        total_p = max(1, len(self.directions))
        direction_ratio = fwd_count / total_p

        # Burstiness: variance of IAT / mean of IAT
        mean_iat = float(np.mean(iat_arr)) if len(iat_arr) > 0 else 0.0
        std_iat = float(np.std(iat_arr)) if len(iat_arr) > 0 else 0.0
        burstiness_index = float(std_iat / (mean_iat + 1e-6)) if mean_iat > 0 else 0.0

        return {
            "packet_count": self.esp_packet_count,
            "byte_count": self.total_bytes,
            "duration_sec": float(duration),
            "avg_packet_size": float(np.mean(sizes)),
            "std_packet_size": float(np.std(sizes)),
            "min_packet_size": int(np.min(sizes)),
            "max_packet_size": int(np.max(sizes)),
            "inter_arrival_mean_ms": float(mean_iat * 1000.0),
            "inter_arrival_std_ms": float(std_iat * 1000.0),
            "burstiness_index": burstiness_index,
            "direction_ratio": direction_ratio,
            "active_spis": list(self.observed_spis.keys()),
            "replay_violations": self.replay_violations_detected
        }
