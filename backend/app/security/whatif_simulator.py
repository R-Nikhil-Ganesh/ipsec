"""
What-If Hardening Simulator
Simulates cryptographic and protocol hardening actions without touching live infrastructure.
Recalculates deterministic security scores and explains remediated vs remaining risks.
"""
from typing import Dict, Any, List, Optional
from app.models.schemas import (
    VPNFingerprint,
    WhatIfRequest,
    WhatIfResult,
    SecurityFinding,
    RiskScoreBreakdown,
)
from app.security.rules_engine import SecurityRulesEngine
from app.security.risk_scorer import RiskScorer
from app.security.baseline import get_current_baseline
from app.utils.constants import DH_GROUPS, STATE_OBSERVED


class WhatIfSimulator:
    @staticmethod
    def simulate(current_fp: VPNFingerprint, req: WhatIfRequest) -> WhatIfResult:
        baseline = get_current_baseline()
        rules_engine = SecurityRulesEngine(baseline)

        # 1. Evaluate Current Baseline
        current_findings = rules_engine.evaluate(current_fp)
        current_risk = RiskScorer.calculate_score(current_findings)

        # 2. Construct Projected Fingerprint
        proj_dict = current_fp.model_dump()

        if req.ike_version is not None:
            proj_dict["ike_version"] = req.ike_version
            proj_dict["ike_version_status"] = STATE_OBSERVED

        if req.encryption is not None:
            proj_dict["encryption"] = req.encryption
            proj_dict["encryption_status"] = STATE_OBSERVED
            # If AEAD, update integrity automatically
            if "GCM" in req.encryption or "POLY1305" in req.encryption:
                proj_dict["integrity"] = "AEAD (Combined Mode)"
                proj_dict["integrity_status"] = STATE_OBSERVED

        if req.integrity is not None:
            proj_dict["integrity"] = req.integrity
            proj_dict["integrity_status"] = STATE_OBSERVED

        if req.dh_group is not None:
            proj_dict["dh_group"] = req.dh_group
            dh_val = int(req.dh_group) if req.dh_group.isdigit() else None
            if dh_val in DH_GROUPS:
                proj_dict["dh_group_name"] = DH_GROUPS[dh_val]["name"]
            else:
                proj_dict["dh_group_name"] = f"DH-Group-{req.dh_group}"
            proj_dict["dh_group_status"] = STATE_OBSERVED

        if req.pfs is not None:
            proj_dict["pfs"] = req.pfs
            proj_dict["pfs_status"] = STATE_OBSERVED

        if req.replay_protection is not None:
            proj_dict["replay_protection"] = req.replay_protection
            proj_dict["replay_protection_status"] = STATE_OBSERVED

        if req.sa_lifetime is not None:
            proj_dict["sa_lifetime"] = req.sa_lifetime
            proj_dict["sa_lifetime_status"] = STATE_OBSERVED

        if req.mode is not None:
            proj_dict["mode"] = req.mode
            proj_dict["mode_status"] = STATE_OBSERVED

        projected_fp = VPNFingerprint(**proj_dict)

        # 3. Evaluate Projected Posture
        projected_findings = rules_engine.evaluate(projected_fp)
        projected_risk = RiskScorer.calculate_score(projected_findings)

        # 4. Compare Findings
        curr_finding_ids = {f.id for f in current_findings}
        proj_finding_ids = {f.id for f in projected_findings}

        resolved_findings = [f for f in current_findings if f.id not in proj_finding_ids]
        remaining_findings = [f for f in projected_findings if f.id in curr_finding_ids]
        new_findings = [f for f in projected_findings if f.id not in curr_finding_ids]

        # 5. Build Hardening Guidance
        guidance = []
        if req.encryption and ("GCM" in req.encryption or "POLY1305" in req.encryption):
            guidance.append(f"Switching to {req.encryption} activates AEAD, eliminating CBC padding oracle attacks and boosting throughput via AES-NI.")
        if req.dh_group and req.dh_group in ("19", "20", "21", "31"):
            guidance.append(f"Diffie-Hellman Group {req.dh_group} provides elliptic-curve discrete log protection, mitigating Logjam precomputation risks.")
        if req.pfs is True:
            guidance.append("Enforcing PFS ensures compromise of long-term credentials cannot decrypt prior recorded network traces.")
        if req.ike_version == "IKEv2":
            guidance.append("Upgrading to IKEv2 reduces handshake packet overhead, fixes NAT traversal, and eliminates IKEv1 PSK dictionary vulnerabilities.")

        # 6. Generate strongSwan configuration snippet
        config_snippet = WhatIfSimulator._generate_config_snippet(projected_fp)

        score_delta = projected_risk.overall_score - current_risk.overall_score

        return WhatIfResult(
            current_score=current_risk.overall_score,
            projected_score=projected_risk.overall_score,
            score_delta=score_delta,
            current_grade=current_risk.posture_grade,
            projected_grade=projected_risk.posture_grade,
            resolved_findings=resolved_findings,
            remaining_findings=remaining_findings,
            new_findings=new_findings,
            projected_breakdown=projected_risk,
            hardening_guidance=guidance,
            config_snippet=config_snippet
        )

    @staticmethod
    def _generate_config_snippet(fp: VPNFingerprint) -> str:
        ike_prop = "aes256gcm16-prfsha256-ecp256"
        esp_prop = "aes256gcm16-ecp256"

        if fp.encryption:
            enc = fp.encryption.lower().replace("-", "")
            if "cbc" in enc:
                esp_prop = f"{enc}-sha256"
            elif "gcm" in enc:
                esp_prop = f"{enc}"

        if fp.dh_group:
            if fp.dh_group in ("19", "20"):
                esp_prop += f"-ecp{fp.dh_group}"
            elif fp.dh_group == "14":
                esp_prop += "-modp2048"

        ver = "2" if fp.ike_version == "IKEv2" else "1"
        rekey = fp.sa_lifetime or 3600

        return f"""# ==========================================
# IPsec Sentinel Recommended Hardening Patch
# Target: strongSwan / swanctl.conf
# ==========================================
connections {{
    hardened-ipsec-tunnel {{
        version = {ver}
        proposals = {ike_prop}
        local_addrs  = {fp.peer_info.initiator_ip if fp.peer_info else "%defaultroute"}
        remote_addrs = {fp.peer_info.responder_ip if fp.peer_info else "%any"}

        children {{
            net-tunnel {{
                esp_proposals = {esp_prop}
                mode = {fp.mode.lower() if fp.mode else "tunnel"}
                rekey_time = {rekey}s
                dpd_action = restart
                close_action = start
            }}
        }}
    }}
}}
"""
