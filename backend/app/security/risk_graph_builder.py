"""
Attack and Risk Path Graph Builder
Generates explainable node-edge relationships showing how configuration weaknesses combine
into compound cryptographic or traffic analysis exposures.
"""
from typing import List, Dict, Any
from app.models.schemas import RiskPathGraph, RiskGraphNode, RiskGraphEdge, SecurityFinding, VPNFingerprint


class RiskGraphBuilder:
    @staticmethod
    def build_graph(fp: VPNFingerprint, findings: List[SecurityFinding]) -> RiskPathGraph:
        nodes: List[RiskGraphNode] = []
        edges: List[RiskGraphEdge] = []
        node_ids = set()

        def add_node(nid: str, label: str, cat: str, sev: str, details: str):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append(RiskGraphNode(id=nid, label=label, category=cat, severity=sev, details=details))

        # Root Endpoint / Tunnel nodes
        add_node(
            "node-vpn-root",
            f"IPsec VPN ({fp.mode or 'Tunnel'} Mode)",
            "Architecture",
            "Informational",
            f"Active tunnel between {fp.peer_info.initiator_ip if fp.peer_info else 'Peer A'} and {fp.peer_info.responder_ip if fp.peer_info else 'Peer B'}"
        )

        has_weak_dh = any("DH" in f.id and f.severity in ("Critical", "High", "Medium") for f in findings)
        has_no_pfs = any("PFS" in f.id and f.severity in ("Critical", "High") for f in findings)
        has_long_life = any("LFT" in f.id for f in findings)
        has_weak_crypto = any("CRY" in f.id and f.severity in ("Critical", "High") for f in findings)
        has_ikev1 = fp.ike_version == "IKEv1"
        has_replay_fail = fp.replay_protection is False

        # DH Chain
        if has_weak_dh:
            add_node(
                "node-dh-weak",
                f"Weak DH Group ({fp.dh_group_name or fp.dh_group})",
                "Key Exchange",
                "Critical",
                "1024-bit prime or legacy group vulnerable to precomputed discrete log (Logjam)"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-dh-weak",
                label="uses negotiated"
            ))

            add_node(
                "node-ke-compromise",
                "Phase 1 Key Compromise Risk",
                "Cryptanalysis",
                "High",
                "Adversary can compute master Diffie-Hellman shared secret"
            )
            edges.append(RiskGraphEdge(
                source="node-dh-weak",
                target="node-ke-compromise",
                label="enables"
            ))

        # PFS Node
        if has_no_pfs:
            add_node(
                "node-no-pfs",
                "PFS Disabled in Child SA",
                "Forward Secrecy",
                "High",
                "Child SAs reuse Phase 1 key material without fresh DH exchange"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-no-pfs",
                label="configured without"
            ))

            if has_weak_dh:
                add_node(
                    "node-retro-decrypt",
                    "Retrospective Bulk Decryption",
                    "Impact",
                    "Critical",
                    "Single key breach allows adversary to retroactively decrypt all recorded historical sessions"
                )
                edges.append(RiskGraphEdge(
                    source="node-ke-compromise",
                    target="node-retro-decrypt",
                    label="amplifies"
                ))
                edges.append(RiskGraphEdge(
                    source="node-no-pfs",
                    target="node-retro-decrypt",
                    label="enables across sessions"
                ))

        # Lifetime exposure
        if has_long_life:
            add_node(
                "node-long-life",
                f"Extended SA Lifetime ({fp.sa_lifetime}s)",
                "Lifetime",
                "Medium",
                "Prolonged session key usage provides large ciphertext sample sizes for cryptanalysis"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-long-life",
                label="operates with"
            ))
            if has_weak_crypto:
                add_node(
                    "node-collision-risk",
                    "Ciphertext Birthday Collision",
                    "Cryptanalysis",
                    "High",
                    "Vast ciphertext blocks under 64-bit cipher enable Sweet32 plaintext recovery"
                )
                edges.append(RiskGraphEdge(
                    source="node-long-life",
                    target="node-collision-risk",
                    label="increases sample pool"
                ))

        # Weak Crypto
        if has_weak_crypto:
            add_node(
                "node-cipher-weak",
                f"Vulnerable Cipher ({fp.encryption})",
                "Cryptography",
                "Critical",
                "Deprecated 64-bit block cipher or single-DES with short key length"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-cipher-weak",
                label="encrypts using"
            ))

        # IKEv1
        if has_ikev1:
            add_node(
                "node-ikev1",
                "Deprecated IKEv1 Protocol",
                "Protocol",
                "High",
                "Prone to offline dictionary attack if PSK; lacks modern security extensions"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-ikev1",
                label="negotiated via"
            ))

        # Replay failure
        if has_replay_fail:
            add_node(
                "node-replay-fail",
                "Anti-Replay Window Violation",
                "Integrity",
                "Critical",
                "Duplicate sequence numbers detected; active network adversary can reinject valid packets"
            )
            edges.append(RiskGraphEdge(
                source="node-vpn-root",
                target="node-replay-fail",
                label="vulnerable to"
            ))

        # If clean / modern configuration
        if not nodes or len(nodes) == 1:
            add_node(
                "node-strong-crypto",
                f"Modern AEAD ({fp.encryption or 'AES-256-GCM'})",
                "Cryptography",
                "Informational",
                "Strong 128/256-bit authenticated encryption"
            )
            add_node(
                "node-strong-dh",
                f"Elliptic Curve DH ({fp.dh_group_name or 'Group 19'})",
                "Key Exchange",
                "Informational",
                "Quantum-resistant discrete log posture with PFS active"
            )
            add_node(
                "node-hardened-posture",
                "High Security Posture",
                "Impact",
                "Informational",
                "Tunnel complies with NIST SP 800-77 Rev. 1 and CNSA Suite"
            )
            edges.append(RiskGraphEdge(source="node-vpn-root", target="node-strong-crypto", label="uses"))
            edges.append(RiskGraphEdge(source="node-vpn-root", target="node-strong-dh", label="exchanges via"))
            edges.append(RiskGraphEdge(source="node-strong-crypto", target="node-hardened-posture", label="achieves"))
            edges.append(RiskGraphEdge(source="node-strong-dh", target="node-hardened-posture", label="secures"))

        return RiskPathGraph(nodes=nodes, edges=edges)
