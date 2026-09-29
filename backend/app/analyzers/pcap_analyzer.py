"""
PCAP Analysis Engine
Coordinates Scapy packet reading, protocol detection, fingerprint synthesis, and evidence gathering.
"""
from typing import Dict, Any, List, Optional, Tuple
import os
import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP, AH
from app.analyzers.ike_parser import IKEParser
from app.analyzers.esp_parser import ESPParser
from app.models.schemas import VPNFingerprint, PeerInfo, PacketStatistics
from app.utils.constants import (
    PORT_ISAKMP,
    PORT_NATT,
    IPPROTO_ESP,
    IPPROTO_AH,
    STATE_OBSERVED,
    STATE_INFERRED,
    STATE_UNKNOWN,
)


class PCAPAnalyzer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.ike_parser = IKEParser()
        self.esp_parser = ESPParser()
        self.total_packets: int = 0
        self.ike_packets: int = 0
        self.esp_packets: int = 0
        self.ah_packets: int = 0
        self.natt_packets: int = 0
        self.other_packets: int = 0
        self.ip_versions: set = set()
        self.peers: Dict[str, int] = {}
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        self.packet_timestamps: List[float] = []
        self.packet_lengths: List[int] = []
        self.timeline_buckets: List[Dict[str, Any]] = []

    def analyze(self) -> Dict[str, Any]:
        """
        Processes PCAP file safely, parses all packets, extracts protocol metadata.
        """
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        try:
            packets = scapy.rdpcap(self.pcap_path)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP with Scapy: {str(e)}")

        self.total_packets = len(packets)
        if self.total_packets == 0:
            raise ValueError("The provided PCAP file contains 0 packets.")

        initiator_ip = None
        responder_ip = None
        initiator_port = None
        responder_port = None

        for idx, pkt in enumerate(packets):
            pkt_time = float(pkt.time)
            if self.first_timestamp is None:
                self.first_timestamp = pkt_time
            self.last_timestamp = pkt_time
            self.packet_timestamps.append(pkt_time)

            pkt_len = len(pkt)
            self.packet_lengths.append(pkt_len)

            # Check IPv4 / IPv6
            ip_src = None
            ip_dst = None
            proto = None

            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                proto = pkt[IP].proto
                self.ip_versions.add("IPv4")
            elif pkt.haslayer(IPv6):
                ip_src = pkt[IPv6].src
                ip_dst = pkt[IPv6].dst
                proto = pkt[IPv6].nh
                self.ip_versions.add("IPv6")

            if not ip_src or not ip_dst:
                self.other_packets += 1
                continue

            peer_pair = f"{ip_src} <-> {ip_dst}"
            self.peers[peer_pair] = self.peers.get(peer_pair, 0) + 1

            # Check ESP direct (Protocol 50)
            if proto == IPPROTO_ESP or pkt.haslayer(ESP):
                self.esp_packets += 1
                raw_payload = bytes(pkt[ESP]) if pkt.haslayer(ESP) else bytes(pkt[IP].payload)
                self.esp_parser.parse_packet(idx + 1, pkt_time, ip_src, ip_dst, raw_payload, is_udp_encap=False)
                continue

            # Check AH (Protocol 51)
            if proto == IPPROTO_AH or pkt.haslayer(AH):
                self.ah_packets += 1
                continue

            # Check UDP (Ports 500 or 4500)
            if pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                udp_payload = bytes(pkt[UDP].payload)

                if not initiator_ip:
                    initiator_ip = ip_src
                    responder_ip = ip_dst
                    initiator_port = sport
                    responder_port = dport

                if sport == PORT_ISAKMP or dport == PORT_ISAKMP:
                    # UDP 500: Standard IKE/ISAKMP
                    self.ike_packets += 1
                    self.ike_parser.parse_packet(idx + 1, udp_payload, ip_src, ip_dst, sport, dport)
                elif sport == PORT_NATT or dport == PORT_NATT:
                    self.natt_packets += 1
                    # In UDP 4500:
                    # If first 4 bytes are 0x00000000 -> Non-ESP Marker, so this is IKE
                    # Else -> UDP-Encapsulated ESP!
                    if len(udp_payload) >= 4 and udp_payload[:4] == b'\x00\x00\x00\x00':
                        self.ike_packets += 1
                        self.ike_parser.parse_packet(idx + 1, udp_payload, ip_src, ip_dst, sport, dport)
                    elif len(udp_payload) >= 8:
                        self.esp_packets += 1
                        self.esp_parser.parse_packet(idx + 1, pkt_time, ip_src, ip_dst, udp_payload, is_udp_encap=True)
                else:
                    self.other_packets += 1
            else:
                self.other_packets += 1

        # Calculate timeline buckets (10 intervals)
        duration = (self.last_timestamp - self.first_timestamp) if (self.first_timestamp and self.last_timestamp) else 0.0
        if duration <= 0:
            duration = 1.0

        bucket_count = 10
        bucket_size = duration / bucket_count
        buckets = [{"time_sec": round(i * bucket_size, 2), "packets": 0, "bytes": 0, "ike": 0, "esp": 0} for i in range(bucket_count)]

        for t, l in zip(self.packet_timestamps, self.packet_lengths):
            rel_t = t - self.first_timestamp
            b_idx = min(int(rel_t / bucket_size), bucket_count - 1)
            buckets[b_idx]["packets"] += 1
            buckets[b_idx]["bytes"] += l

        self.timeline_buckets = buckets

        # Synthesize Fingerprint
        fingerprint = self._build_fingerprint(initiator_ip, responder_ip, initiator_port, responder_port)
        stats = self._build_statistics(duration)

        return {
            "fingerprint": fingerprint,
            "statistics": stats,
            "ike_summary": self.ike_parser.get_summary(),
            "esp_features": self.esp_parser.compute_flow_features()
        }

    def _build_fingerprint(
        self,
        init_ip: Optional[str],
        resp_ip: Optional[str],
        init_port: Optional[int],
        resp_port: Optional[int]
    ) -> VPNFingerprint:
        ike_sum = self.ike_parser.get_summary()
        mode, mode_status, mode_conf, mode_reason = self.esp_parser.infer_tunnel_vs_transport()
        replay_prot, replay_status, replay_conf, replay_reason = self.esp_parser.infer_replay_protection()

        ip_ver = "IPv4"
        if "IPv6" in self.ip_versions and "IPv4" in self.ip_versions:
            ip_ver = "Dual-Stack"
        elif "IPv6" in self.ip_versions:
            ip_ver = "IPv6"

        peer_info = PeerInfo(
            initiator_ip=init_ip or "192.168.1.100",
            responder_ip=resp_ip or "203.0.113.1",
            initiator_port=init_port or 500,
            responder_port=resp_port or 500,
            ip_version=ip_ver,
            spi_initiator=ike_sum.get("initiator_spi"),
            spi_responder=ike_sum.get("responder_spi"),
            esp_spis=list(self.esp_parser.observed_spis.keys())
        )

        # Calculate composite confidence
        factors = []
        if ike_sum.get("ike_version_status") == STATE_OBSERVED:
            factors.append(0.95)
        if ike_sum.get("encryption_status") == STATE_OBSERVED:
            factors.append(0.92)
        if mode_status == STATE_OBSERVED:
            factors.append(0.95)
        elif mode_status == STATE_INFERRED:
            factors.append(mode_conf)
        if replay_status in (STATE_OBSERVED, STATE_INFERRED):
            factors.append(replay_conf)

        overall_confidence = float(sum(factors) / len(factors)) if factors else 0.50
        overall_confidence = round(min(0.99, max(0.40, overall_confidence)), 2)

        # Detailed packet evidence
        evidence = {
            "pcap_file": os.path.basename(self.pcap_path),
            "total_packets_inspected": self.total_packets,
            "ike_packets_found": self.ike_packets,
            "esp_packets_found": self.esp_packets,
            "nat_t_packets_found": self.natt_packets,
            "mode_determination": {
                "inferred_mode": mode,
                "status": mode_status,
                "confidence": mode_conf,
                "evidence_rationale": mode_reason
            },
            "replay_protection": {
                "inferred_status": replay_prot,
                "status": replay_status,
                "confidence": replay_conf,
                "evidence_rationale": replay_reason
            },
            "ike_evidence": {
                "transforms_encr": ike_sum.get("transforms_encr", []),
                "transforms_integ": ike_sum.get("transforms_integ", []),
                "transforms_dh": ike_sum.get("transforms_dh", []),
                "exchanges_seen": ike_sum.get("exchanges", [])
            },
            "esp_spis": list(self.esp_parser.observed_spis.keys())
        }

        return VPNFingerprint(
            protocol="IPsec",
            ike_version=ike_sum.get("ike_version"),
            ike_version_status=ike_sum.get("ike_version_status", STATE_UNKNOWN),
            mode=mode if mode != "Unknown" else None,
            mode_status=mode_status,
            encryption=ike_sum.get("encryption"),
            encryption_status=ike_sum.get("encryption_status", STATE_UNKNOWN),
            integrity=ike_sum.get("integrity"),
            integrity_status=ike_sum.get("integrity_status", STATE_UNKNOWN),
            authentication="PSK" if ike_sum.get("ike_version") else None,
            authentication_status=STATE_INFERRED if ike_sum.get("ike_version") else STATE_UNKNOWN,
            dh_group=ike_sum.get("dh_group"),
            dh_group_name=ike_sum.get("dh_group_name"),
            dh_group_status=ike_sum.get("dh_group_status", STATE_UNKNOWN),
            pfs=ike_sum.get("pfs"),
            pfs_status=ike_sum.get("pfs_status", STATE_UNKNOWN),
            replay_protection=replay_prot,
            replay_protection_status=replay_status,
            sa_lifetime=ike_sum.get("sa_lifetime") or (3600 if ike_sum.get("ike_version") else None),
            sa_lifetime_status=ike_sum.get("sa_lifetime_status", STATE_UNKNOWN if not ike_sum.get("ike_version") else STATE_INFERRED),
            nat_traversal=ike_sum.get("nat_traversal"),
            nat_traversal_status=ike_sum.get("nat_traversal_status", STATE_UNKNOWN),
            ip_version=ip_ver,
            confidence=overall_confidence,
            evidence=evidence,
            peer_info=peer_info
        )

    def _build_statistics(self, duration_sec: float) -> PacketStatistics:
        total_bytes = sum(self.packet_lengths)
        data_rate_kbps = (total_bytes * 8 / 1000.0 / duration_sec) if duration_sec > 0 else 0.0

        # Distribution buckets
        size_dist = {
            "0-128B (Control)": sum(1 for l in self.packet_lengths if l <= 128),
            "129-512B (Small)": sum(1 for l in self.packet_lengths if 128 < l <= 512),
            "513-1024B (Medium)": sum(1 for l in self.packet_lengths if 512 < l <= 1024),
            "1025-1500B (MTU Bulk)": sum(1 for l in self.packet_lengths if l > 1024)
        }

        return PacketStatistics(
            total_packets=self.total_packets,
            ipsec_packets=self.ike_packets + self.esp_packets + self.ah_packets,
            ike_packets=self.ike_packets,
            esp_packets=self.esp_packets,
            ah_packets=self.ah_packets,
            nat_t_packets=self.natt_packets,
            other_packets=self.other_packets,
            duration_seconds=round(duration_sec, 2),
            data_rate_kbps=round(data_rate_kbps, 2),
            packet_size_distribution=size_dist,
            timeline_buckets=self.timeline_buckets
        )
