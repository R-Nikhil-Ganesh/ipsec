"""
Deterministic Security Rules Engine
Evaluates VPN cryptographic parameters, protocol versions, PFS, replay protection,
and lifetimes against security best practices and compliance baselines.
"""
from typing import List, Dict, Any, Optional
from app.models.schemas import VPNFingerprint, SecurityFinding, BaselineConfig
from app.utils.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    DH_GROUPS,
)


class SecurityRulesEngine:
    def __init__(self, baseline: BaselineConfig):
        self.baseline = baseline

    def evaluate(self, fp: VPNFingerprint) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # 1. Protocol / IKE Version Checks
        if fp.ike_version == "IKEv1":
            findings.append(SecurityFinding(
                id="SEC-IKE-001",
                title="Deprecated IKEv1 Protocol in Use",
                category="Protocol",
                severity=SEVERITY_HIGH,
                score_impact=-15,
                evidence=f"Observed IKE version is '{fp.ike_version}' (Status: {fp.ike_version_status})",
                confidence=0.96,
                why_it_matters="IKEv1 is officially deprecated by IETF (RFC 9395). It is susceptible to offline dictionary attacks when using PSKs, lacks native NAT-T standardization, has higher handshake round-trips (6 packets vs 4 in IKEv2), and does not support modern asymmetric authentication flexibly.",
                remediation="Upgrade the VPN gateway configuration to IKEv2 (RFC 7296). Disable IKEv1 daemons and listeners.",
                remediation_patch="""# strongSwan / swanctl.conf
connections {
    ipsec-vpn {
        version = 2
        proposals = aes256gcm16-prfsha256-ecp256
    }
}"""
            ))
        elif not fp.ike_version and fp.protocol == "IPsec":
            findings.append(SecurityFinding(
                id="SEC-IKE-002",
                title="IKE Version Unobserved in Capture",
                category="Protocol",
                severity=SEVERITY_INFO,
                score_impact=0,
                evidence="No UDP/500 or UDP/4500 IKE negotiation packets were captured in this trace",
                confidence=0.70,
                why_it_matters="Without IKE handshake packets, Phase 1 negotiation parameters cannot be directly validated; analysis is relying on ESP/traffic heuristics.",
                remediation="Capture the initial VPN tunnel establishment (IKE_SA_INIT and IKE_AUTH) to verify key exchange parameters.",
                remediation_patch=None
            ))

        # 2. Cryptographic Encryption Algorithm Checks
        encr = (fp.encryption or "").upper()
        if "DES" in encr and "3DES" not in encr:
            findings.append(SecurityFinding(
                id="SEC-CRY-001",
                title="Critical Weakness: Single DES Encryption Detected",
                category="Cryptography",
                severity=SEVERITY_CRITICAL,
                score_impact=-30,
                evidence=f"Observed cipher '{fp.encryption}' (Status: {fp.encryption_status})",
                confidence=0.98,
                why_it_matters="Single DES has a 56-bit key length and can be broken in hours using cloud compute (COPACOBANA / CrackStation). It provides zero real-world confidentiality against adversaries.",
                remediation="Immediately replace DES with an AEAD cipher such as AES-256-GCM or ChaCha20-Poly1305.",
                remediation_patch="esp = aes256gcm16-ecp256!"
            ))
        elif "3DES" in encr:
            findings.append(SecurityFinding(
                id="SEC-CRY-002",
                title="High Risk: Legacy 3DES Cipher Detected (Sweet32 Vulnerability)",
                category="Cryptography",
                severity=SEVERITY_HIGH,
                score_impact=-20,
                evidence=f"Observed cipher '{fp.encryption}' (Status: {fp.encryption_status})",
                confidence=0.98,
                why_it_matters="Triple-DES (3DES) uses a 64-bit block size making it fundamentally vulnerable to birthday collision attacks (CVE-2016-2183 / Sweet32) when transmitting large amounts of data. NIST has officially deprecated 3DES after 2023.",
                remediation="Upgrade transform proposal to AES-256-GCM (128-bit block, 256-bit key).",
                remediation_patch="esp = aes256gcm16-sha256-modp2048!"
            ))
        elif "NULL" in encr:
            findings.append(SecurityFinding(
                id="SEC-CRY-003",
                title="Critical: ESP NULL Encryption (Cleartext VPN)",
                category="Cryptography",
                severity=SEVERITY_CRITICAL,
                score_impact=-40,
                evidence=f"Observed cipher '{fp.encryption}' (Status: {fp.encryption_status})",
                confidence=0.99,
                why_it_matters="ESP NULL provides integrity/authentication only, completely exposing inner tunneled traffic payloads to eavesdropping across the transit network.",
                remediation="Disable NULL encryption in proposal sets and enforce AES-256-GCM.",
                remediation_patch="esp = aes256gcm16!"
            ))
        elif "CBC" in encr:
            findings.append(SecurityFinding(
                id="SEC-CRY-004",
                title="Legacy Cipher Mode: AES-CBC Detected",
                category="Cryptography",
                severity=SEVERITY_MEDIUM,
                score_impact=-8,
                evidence=f"Observed cipher '{fp.encryption}' (Status: {fp.encryption_status})",
                confidence=0.95,
                why_it_matters="CBC mode is susceptible to padding oracle attacks if integrity verification is not strictly implemented as Encrypt-then-MAC. Modern AEAD modes (AES-GCM) provide authenticated encryption intrinsically without separate padding vulnerabilities.",
                remediation="Migrate cipher suite from AES-CBC to AES-GCM (AEAD).",
                remediation_patch="esp = aes256gcm16,aes128gcm16!"
            ))
        elif "GCM" in encr or "POLY1305" in encr:
            findings.append(SecurityFinding(
                id="SEC-CRY-005",
                title="Compliant Modern AEAD Cryptography Active",
                category="Cryptography",
                severity=SEVERITY_INFO,
                score_impact=0,
                evidence=f"Observed modern AEAD cipher '{fp.encryption}' (Status: {fp.encryption_status})",
                confidence=0.95,
                why_it_matters="AES-GCM / ChaCha20-Poly1305 provides authenticated encryption with associated data (AEAD), combining confidentiality and data origin authentication with high hardware acceleration performance (AES-NI).",
                remediation="Maintain current AEAD cipher configuration and keep crypto libraries updated.",
                remediation_patch=None
            ))

        # 3. Integrity / Authentication Checks
        integ = (fp.integrity or "").upper()
        if "MD5" in integ:
            findings.append(SecurityFinding(
                id="SEC-INT-001",
                title="High Risk: Broken HMAC-MD5 Integrity Protection",
                category="Integrity",
                severity=SEVERITY_HIGH,
                score_impact=-15,
                evidence=f"Observed integrity transform '{fp.integrity}' (Status: {fp.integrity_status})",
                confidence=0.98,
                why_it_matters="MD5 is cryptographically compromised with practical collision attacks. While HMAC constructs reduce collision severity, MD5 is strictly disallowed under NIST SP 800-131A and PCI-DSS requirements.",
                remediation="Enforce SHA-2 family integrity (HMAC-SHA2-256) or migrate to AEAD ciphers.",
                remediation_patch="ah = sha256!\nesp = aes256-sha256!"
            ))
        elif "SHA1" in integ or "SHA-1" in integ:
            findings.append(SecurityFinding(
                id="SEC-INT-002",
                title="Medium Risk: Deprecated HMAC-SHA1 Integrity Algorithm",
                category="Integrity",
                severity=SEVERITY_MEDIUM,
                score_impact=-10,
                evidence=f"Observed integrity transform '{fp.integrity}' (Status: {fp.integrity_status})",
                confidence=0.95,
                why_it_matters="SHA-1 has theoretical chosen-prefix collisions (SHAttered attack). NIST declared SHA-1 deprecated for all cryptographic applications and mandates phase-out by 2030.",
                remediation="Upgrade to HMAC-SHA2-256 or use native AEAD (AES-GCM).",
                remediation_patch="esp = aes256gcm16!"
            ))

        # 4. Diffie-Hellman Key Exchange Group Checks
        dh_str = str(fp.dh_group or "")
        dh_num = int(dh_str) if dh_str.isdigit() else None

        if dh_num in (1, 2):
            dh_name = DH_GROUPS.get(dh_num, {}).get("name", f"Group-{dh_num}")
            findings.append(SecurityFinding(
                id="SEC-DH-001",
                title=f"Critical Risk: Insecure Diffie-Hellman Group ({dh_name})",
                category="Key Exchange",
                severity=SEVERITY_CRITICAL,
                score_impact=-25,
                evidence=f"Observed DH group '{dh_str}' - {dh_name} (Status: {fp.dh_group_status})",
                confidence=0.97,
                why_it_matters="DH Groups 1 (768-bit) and 2 (1024-bit) are susceptible to discrete logarithm precomputation attacks (Logjam). Nation-state actors and well-funded attackers can actively compromise or passive-decrypt ephemeral session keys negotiated over 1024-bit primes.",
                remediation="Upgrade DH group to at least Group 14 (MODP 2048-bit) or preferably Group 19 (ECP-256) / Group 20 (ECP-384).",
                remediation_patch="ike = aes256gcm16-prfsha256-ecp256!"
            ))
        elif dh_num == 5:
            findings.append(SecurityFinding(
                id="SEC-DH-002",
                title="Medium Risk: Insufficient Diffie-Hellman Group 5 (1536-bit MODP)",
                category="Key Exchange",
                severity=SEVERITY_MEDIUM,
                score_impact=-10,
                evidence=f"Observed DH group '5' (Status: {fp.dh_group_status})",
                confidence=0.95,
                why_it_matters="DH Group 5 provides approximately 80 to 90 bits of symmetric security, falling short of the standard 128-bit security floor required for modern infrastructure.",
                remediation="Upgrade to Group 14 (MODP 2048) or Group 19 (ECP-256 / secp256r1).",
                remediation_patch="ike = aes256gcm16-prfsha256-ecp256!"
            ))
        elif dh_num in (19, 20, 21, 31):
            findings.append(SecurityFinding(
                id="SEC-DH-003",
                title=f"Strong Modern Elliptic Curve Key Exchange (Group {dh_num})",
                category="Key Exchange",
                severity=SEVERITY_INFO,
                score_impact=0,
                evidence=f"Observed DH group '{dh_str}' ({fp.dh_group_name})",
                confidence=0.95,
                why_it_matters="Elliptic curve Diffie-Hellman (ECP-256 / Curve25519) provides 128+ bit quantum-resistant symmetric security equivalence with minimal computational overhead and resistance to timing attacks.",
                remediation="Maintain configuration in adherence with NSA Commercial National Security Algorithm (CNSA) Suite.",
                remediation_patch=None
            ))

        # 5. Perfect Forward Secrecy (PFS) Checks
        if fp.pfs is False:
            findings.append(SecurityFinding(
                id="SEC-PFS-001",
                title="High Risk: Perfect Forward Secrecy (PFS) Disabled",
                category="Key Exchange",
                severity=SEVERITY_HIGH,
                score_impact=-15,
                evidence=f"PFS status evaluated as {fp.pfs} (Status: {fp.pfs_status})",
                confidence=0.90,
                why_it_matters="Without PFS, Child SAs derive their session encryption keys directly from the Phase 1 master key without performing a fresh Diffie-Hellman exchange. If the long-term private key or Phase 1 secret is ever compromised, ALL historical recorded traffic can be retrospectively decrypted.",
                remediation="Enable PFS in IPsec Child SA proposals (require a fresh DH group exchange for Phase 2 / Child SAs).",
                remediation_patch="""# strongSwan configuration
children {
    ipsec-child {
        esp_proposals = aes256gcm16-ecp256! # The ecp256 enforces Phase 2 PFS
    }
}"""
            ))
        elif fp.pfs is True:
            findings.append(SecurityFinding(
                id="SEC-PFS-002",
                title="Perfect Forward Secrecy (PFS) Enforced",
                category="Key Exchange",
                severity=SEVERITY_INFO,
                score_impact=0,
                evidence=f"Observed separate Diffie-Hellman exchange during Child SA establishment",
                confidence=0.92,
                why_it_matters="PFS guarantees that the compromise of a single session key or long-term private key does not compromise past or future sessions.",
                remediation="Keep PFS enforced across all tunnel interfaces.",
                remediation_patch=None
            ))

        # 6. Anti-Replay Protection Checks
        if fp.replay_protection is False:
            findings.append(SecurityFinding(
                id="SEC-REP-001",
                title="Critical: Replay Protection Inactive or Violations Detected",
                category="Replay",
                severity=SEVERITY_CRITICAL,
                score_impact=-20,
                evidence=f"Replay protection status: {fp.replay_protection} (Duplicate sequence numbers detected in ESP headers)",
                confidence=0.95,
                why_it_matters="Without active anti-replay sliding window validation, an attacker on the transit network can capture valid encrypted ESP packets and re-inject them at will, leading to service disruption, duplicate transactions, or protocol state desynchronization.",
                remediation="Enable IPsec Anti-Replay sliding window mechanism (default 32 or 64 packet window size).",
                remediation_patch="replay_window = 64"
            ))

        # 7. Security Association (SA) Lifetime Checks
        if fp.sa_lifetime:
            if fp.sa_lifetime > self.baseline.max_sa_lifetime:
                findings.append(SecurityFinding(
                    id="SEC-LFT-001",
                    title=f"Excessive SA Lifetime ({fp.sa_lifetime}s > {self.baseline.max_sa_lifetime}s)",
                    category="Lifetime",
                    severity=SEVERITY_MEDIUM,
                    score_impact=-8,
                    evidence=f"Observed SA lifetime: {fp.sa_lifetime} seconds (Maximum allowed in baseline: {self.baseline.max_sa_lifetime}s)",
                    confidence=0.90,
                    why_it_matters="Long-lived Security Associations increase cryptographic exposure by encrypting vast quantities of data under identical keys, providing cryptanalysts with larger statistical sample sizes and extending the window of vulnerability if a key is compromised.",
                    remediation=f"Configure SA lifetime to rotate every 1 to 4 hours (e.g., 3600 to 14400 seconds).",
                    remediation_patch="rekey_time = 3600s\nrekey_bytes = 10G"
                ))
            elif fp.sa_lifetime < self.baseline.min_sa_lifetime and fp.sa_lifetime > 0:
                findings.append(SecurityFinding(
                    id="SEC-LFT-002",
                    title=f"Unusually Short SA Lifetime ({fp.sa_lifetime}s < {self.baseline.min_sa_lifetime}s)",
                    category="Lifetime",
                    severity=SEVERITY_LOW,
                    score_impact=-3,
                    evidence=f"Observed SA lifetime: {fp.sa_lifetime} seconds",
                    confidence=0.85,
                    why_it_matters="Extremely frequent rekeying causes unnecessary CPU utilization on VPN gateways and may cause transient packet drops or out-of-order delivery during rapid renegotiations.",
                    remediation="Tune SA lifetime to standard 3600s (1 hour) baseline.",
                    remediation_patch="rekey_time = 3600s"
                ))

        return findings
