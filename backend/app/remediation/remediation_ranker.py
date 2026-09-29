"""Ranks remediation plans by their projected security score (highest first)."""
from typing import List

from app.models.temporal_schemas import RemediationPlan


def rank_plans(plans: List[RemediationPlan]) -> List[RemediationPlan]:
    return sorted(plans, key=lambda p: p.whatif_result.projected_score, reverse=True)
