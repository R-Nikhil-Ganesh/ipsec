"""
Automated Remediation Planner
Generates candidate hardening plans and scores each one by delegating entirely to the
existing, stateless WhatIfSimulator/RiskGraphBuilder — no second scoring engine.
"""
from typing import List

from app.models.schemas import VPNFingerprint, SecurityFinding, WhatIfRequest, RiskPathGraph
from app.models.temporal_schemas import RemediationPlan, RemediationChange
from app.security.whatif_simulator import WhatIfSimulator
from app.security.risk_graph_builder import RiskGraphBuilder
from app.security.baseline import get_current_baseline

_TRACKED_FIELDS = ("ike_version", "encryption", "dh_group", "pfs", "replay_protection", "sa_lifetime")


def _plan_from_request(
    plan_id: str,
    label: str,
    problem_summary: str,
    current_fp: VPNFingerprint,
    current_graph: RiskPathGraph,
    req: WhatIfRequest,
) -> RemediationPlan:
    result = WhatIfSimulator.simulate(current_fp, req)

    current_dict = current_fp.model_dump()
    changes: List[RemediationChange] = []
    proj_dict = dict(current_dict)
    for field in _TRACKED_FIELDS:
        new_val = getattr(req, field)
        if new_val is not None:
            old_val = current_dict.get(field)
            if str(old_val) != str(new_val):
                changes.append(RemediationChange(
                    parameter=field,
                    from_value=str(old_val) if old_val is not None else None,
                    to_value=str(new_val),
                ))
            proj_dict[field] = new_val

    # Recompute the projected risk graph (using the exact finding set the simulator
    # already produced) so we can report how many attack-path nodes/edges it removes.
    projected_findings = result.remaining_findings + result.new_findings
    projected_fp = VPNFingerprint(**proj_dict)
    projected_graph = RiskGraphBuilder.build_graph(projected_fp, projected_findings)

    current_node_ids = {n.id for n in current_graph.nodes}
    projected_node_ids = {n.id for n in projected_graph.nodes}
    current_edge_keys = {(e.source, e.target) for e in current_graph.edges}
    projected_edge_keys = {(e.source, e.target) for e in projected_graph.edges}

    return RemediationPlan(
        plan_id=plan_id,
        label=label,
        problem_summary=problem_summary,
        changes=changes,
        whatif_request=req,
        whatif_result=result,
        findings_resolved=len(result.resolved_findings),
        findings_remaining=len(result.remaining_findings),
        graph_nodes_removed=len(current_node_ids - projected_node_ids),
        graph_edges_removed=len(current_edge_keys - projected_edge_keys),
    )


def build_remediation_plans(
    current_fp: VPNFingerprint,
    findings: List[SecurityFinding],
    current_graph: RiskPathGraph,
) -> List[RemediationPlan]:
    baseline = get_current_baseline()
    preferred_dh = str(baseline.preferred_dh_groups[0]) if baseline.preferred_dh_groups else "19"

    plans = [
        _plan_from_request(
            "plan-a-cipher",
            "Plan A — Restore Encryption Cipher",
            "The negotiated cipher has regressed below the enterprise baseline minimum.",
            current_fp, current_graph,
            WhatIfRequest(encryption=baseline.min_encryption),
        ),
        _plan_from_request(
            "plan-b-cipher-dh",
            "Plan B — Restore Cipher + Key Exchange",
            "Both the cipher and the Diffie-Hellman group have regressed below baseline.",
            current_fp, current_graph,
            WhatIfRequest(encryption=baseline.min_encryption, dh_group=preferred_dh),
        ),
        _plan_from_request(
            "plan-c-full-hardening",
            "Plan C — Full Baseline Hardening",
            "Multiple compounding regressions detected across cipher, key exchange, forward secrecy, and replay protection.",
            current_fp, current_graph,
            WhatIfRequest(
                ike_version=baseline.preferred_ike_version,
                encryption=baseline.min_encryption,
                dh_group=preferred_dh,
                pfs=True,
                replay_protection=True,
                sa_lifetime=baseline.min_sa_lifetime or 3600,
            ),
        ),
    ]
    return plans
