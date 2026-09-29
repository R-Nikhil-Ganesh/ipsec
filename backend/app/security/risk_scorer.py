"""
Transparent Risk Scorer
Computes explainable composite security score from 100 to 0 with explicit point deductions.
"""
from typing import List, Dict, Any
from app.models.schemas import SecurityFinding, RiskScoreBreakdown
from app.utils.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)


class RiskScorer:
    @staticmethod
    def calculate_score(findings: List[SecurityFinding]) -> RiskScoreBreakdown:
        base_score = 100
        total_deduction = 0
        deductions: List[Dict[str, Any]] = []

        category_penalties: Dict[str, int] = {
            "Cryptography": 0,
            "Key Exchange": 0,
            "Protocol": 0,
            "Integrity": 0,
            "Lifetime": 0,
            "Replay": 0,
            "Compliance": 0
        }

        findings_count = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 0,
            SEVERITY_MEDIUM: 0,
            SEVERITY_LOW: 0,
            SEVERITY_INFO: 0
        }

        for f in findings:
            findings_count[f.severity] = findings_count.get(f.severity, 0) + 1
            if f.score_impact < 0:
                penalty = abs(f.score_impact)
                total_deduction += penalty
                category_penalties[f.category] = category_penalties.get(f.category, 0) + penalty
                deductions.append({
                    "finding_id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "penalty": penalty,
                    "reason": f.why_it_matters
                })

        overall_score = max(0, min(100, base_score - total_deduction))

        # Assign letter grade
        if overall_score >= 95:
            grade = "A+"
        elif overall_score >= 85:
            grade = "A"
        elif overall_score >= 70:
            grade = "B"
        elif overall_score >= 55:
            grade = "C"
        elif overall_score >= 40:
            grade = "D"
        else:
            grade = "F"

        # Compute category scores (each out of 100)
        category_scores = {}
        for cat, pen in category_penalties.items():
            category_scores[cat] = max(0, 100 - pen * 3)

        return RiskScoreBreakdown(
            overall_score=overall_score,
            posture_grade=grade,
            base_score=base_score,
            total_penalty=total_deduction,
            category_scores=category_scores,
            findings_count=findings_count,
            score_deductions=deductions
        )
