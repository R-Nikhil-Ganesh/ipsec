"""
Configuration Drift Detector
Compares current VPN Security Fingerprint against an established baseline or prior snapshot.
Detects silent cryptographic downgrades, security regressions, and policy violations.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.schemas import VPNFingerprint, ConfigurationDrift, DriftChange
from app.utils.constants import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


class DriftDetector:
    @staticmethod
    def compare(
        current_fp: VPNFingerprint,
        baseline_fp: Optional[VPNFingerprint] = None,
        baseline_name: str = "Enterprise Golden Baseline"
    ) -> ConfigurationDrift:
        if not baseline_fp:
            # If no prior fingerprint is supplied, check against default ideal baseline
            return ConfigurationDrift(
                has_drift=False,
                baseline_name=baseline_name,
                drift_detected_at=datetime.utcnow().isoformat(),
                changes=[],
                drift_severity="None"
            )

        changes: List[DriftChange] = []
        max_severity = "None"

        # Helper to escalate severity
        def update_max(s: str):
            nonlocal max_severity
            rank = {"None": 0, SEVERITY_INFO: 1, SEVERITY_LOW: 2, SEVERITY_MEDIUM: 3, SEVERITY_HIGH: 4, SEVERITY_CRITICAL: 5}
            if rank.get(s, 0) > rank.get(max_severity, 0):
                max_severity = s

        # 1. Encryption Algorithm Drift
        if baseline_fp.encryption and current_fp.encryption and baseline_fp.encryption != current_fp.encryption:
            cur_enc = current_fp.encryption.upper()
            base_enc = baseline_fp.encryption.upper()
            if ("DES" in cur_enc or "NULL" in cur_enc) and "AES" in base_enc:
                sev = SEVERITY_CRITICAL
                imp = f"Critical cryptographic regression: Tunnel downgraded from secure '{baseline_fp.encryption}' to broken '{current_fp.encryption}'."
            elif "CBC" in cur_enc and "GCM" in base_enc:
                sev = SEVERITY_HIGH
                imp = f"Downgrade from modern AEAD ({baseline_fp.encryption}) to legacy block cipher mode ({current_fp.encryption}), introducing padding oracle risks."
            elif "128" in cur_enc and "256" in base_enc:
                sev = SEVERITY_MEDIUM
                imp = f"Key size reduced from 256 bits to 128 bits ({baseline_fp.encryption} -> {current_fp.encryption})."
            else:
                sev = SEVERITY_LOW
                imp = f"Cipher suite modified from '{baseline_fp.encryption}' to '{current_fp.encryption}'."
            changes.append(DriftChange(
                parameter="Encryption Algorithm",
                previous_value=baseline_fp.encryption,
                current_value=current_fp.encryption,
                severity=sev,
                security_implication=imp
            ))
            update_max(sev)

        # 2. Diffie-Hellman Group Drift
        if baseline_fp.dh_group and current_fp.dh_group and baseline_fp.dh_group != current_fp.dh_group:
            cur_dh = int(current_fp.dh_group) if current_fp.dh_group.isdigit() else 0
            base_dh = int(baseline_fp.dh_group) if baseline_fp.dh_group.isdigit() else 0

            if cur_dh in (1, 2) and base_dh >= 14:
                sev = SEVERITY_CRITICAL
                imp = f"Severe key exchange downgrade: Diffie-Hellman group degraded from Group {baseline_fp.dh_group} to vulnerable Group {current_fp.dh_group} (Logjam exposure)."
            elif cur_dh < base_dh:
                sev = SEVERITY_HIGH
                imp = f"Diffie-Hellman group strength degraded from {baseline_fp.dh_group_name or baseline_fp.dh_group} to {current_fp.dh_group_name or current_fp.dh_group}."
            else:
                sev = SEVERITY_INFO
                imp = f"Diffie-Hellman group modified from Group {baseline_fp.dh_group} to Group {current_fp.dh_group}."
            changes.append(DriftChange(
                parameter="Diffie-Hellman Group",
                previous_value=baseline_fp.dh_group_name or baseline_fp.dh_group,
                current_value=current_fp.dh_group_name or current_fp.dh_group,
                severity=sev,
                security_implication=imp
            ))
            update_max(sev)

        # 3. Perfect Forward Secrecy (PFS) Drift
        if baseline_fp.pfs is True and current_fp.pfs is False:
            sev = SEVERITY_HIGH
            changes.append(DriftChange(
                parameter="Perfect Forward Secrecy (PFS)",
                previous_value="Enabled",
                current_value="Disabled",
                severity=sev,
                security_implication="PFS was disabled in Child SA proposals. Compromise of Phase 1 secret now exposes all historical sessions."
            ))
            update_max(sev)
        elif baseline_fp.pfs is False and current_fp.pfs is True:
            changes.append(DriftChange(
                parameter="Perfect Forward Secrecy (PFS)",
                previous_value="Disabled",
                current_value="Enabled",
                severity=SEVERITY_INFO,
                security_implication="Security enhancement: Perfect Forward Secrecy has been enabled."
            ))

        # 4. IKE Version Drift
        if baseline_fp.ike_version and current_fp.ike_version and baseline_fp.ike_version != current_fp.ike_version:
            if current_fp.ike_version == "IKEv1" and baseline_fp.ike_version == "IKEv2":
                sev = SEVERITY_HIGH
                imp = "Protocol downgrade attack or misconfiguration: VPN rolled back from modern IKEv2 to deprecated IKEv1."
            else:
                sev = SEVERITY_INFO
                imp = f"IKE version updated from {baseline_fp.ike_version} to {current_fp.ike_version}."
            changes.append(DriftChange(
                parameter="IKE Version",
                previous_value=baseline_fp.ike_version,
                current_value=current_fp.ike_version,
                severity=sev,
                security_implication=imp
            ))
            update_max(sev)

        # 5. SA Lifetime Drift
        if baseline_fp.sa_lifetime and current_fp.sa_lifetime and baseline_fp.sa_lifetime != current_fp.sa_lifetime:
            if current_fp.sa_lifetime > baseline_fp.sa_lifetime * 2:
                sev = SEVERITY_MEDIUM
                imp = f"SA Lifetime prolonged from {baseline_fp.sa_lifetime}s to {current_fp.sa_lifetime}s, extending cryptanalytic key exposure window."
                changes.append(DriftChange(
                    parameter="SA Lifetime",
                    previous_value=f"{baseline_fp.sa_lifetime}s",
                    current_value=f"{current_fp.sa_lifetime}s",
                    severity=sev,
                    security_implication=imp
                ))
                update_max(sev)

        # 6. Replay Protection Drift
        if baseline_fp.replay_protection is True and current_fp.replay_protection is False:
            sev = SEVERITY_CRITICAL
            changes.append(DriftChange(
                parameter="Anti-Replay Protection",
                previous_value="Active",
                current_value="Inactive / Violations Detected",
                severity=sev,
                security_implication="Anti-replay sliding window checks failed or duplicate packets detected."
            ))
            update_max(sev)

        has_drift = len(changes) > 0
        return ConfigurationDrift(
            has_drift=has_drift,
            baseline_name=baseline_name,
            drift_detected_at=datetime.utcnow().isoformat() if has_drift else None,
            changes=changes,
            drift_severity=max_severity if has_drift else "None"
        )
