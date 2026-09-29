import React from "react";
import { Calculator, MinusCircle, CheckCircle2 } from "lucide-react";
import { RiskScoreBreakdown } from "../types";

interface ScoreBreakdownCardProps {
  riskScore: RiskScoreBreakdown;
}

export const ScoreBreakdownCard: React.FC<ScoreBreakdownCardProps> = ({ riskScore }) => {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Calculator className="w-4 h-4" />
          </div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Explainable Risk Scoring Breakdown
          </h2>
        </div>
        <div className="text-xs font-mono text-slate-400">
          Formula: <span className="text-slate-200">Base(100) - Penalties = {riskScore.overall_score}</span>
        </div>
      </div>

      {/* Deduction list */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs py-1.5 px-3 bg-slate-950/60 rounded-lg border border-slate-800">
          <span className="text-slate-300 font-medium">Standard Baseline Score</span>
          <span className="font-mono font-bold text-emerald-400">+100</span>
        </div>

        {riskScore.score_deductions.length === 0 ? (
          <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg flex items-center space-x-2 text-xs text-emerald-300">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>Zero deductions! Tunnel strictly adheres to preferred enterprise security baseline.</span>
          </div>
        ) : (
          riskScore.score_deductions.map((d, i) => (
            <div
              key={i}
              className="flex items-start justify-between text-xs py-2 px-3 bg-slate-950/40 rounded-lg border border-slate-800/80 space-x-3"
            >
              <div className="flex items-start space-x-2">
                <MinusCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-slate-200">{d.title}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{d.reason.slice(0, 100)}...</div>
                </div>
              </div>
              <span className="font-mono font-bold text-rose-400 shrink-0">-{d.penalty} pts</span>
            </div>
          ))
        )}
      </div>

      {/* Category Sub-scores */}
      <div className="pt-2 border-t border-slate-800">
        <h3 className="text-[11px] uppercase tracking-wider font-bold text-slate-400 mb-2">
          Category Health Breakdown
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {Object.entries(riskScore.category_scores).map(([cat, val]) => (
            <div key={cat} className="p-2 bg-slate-950/60 border border-slate-800 rounded-lg">
              <div className="flex justify-between items-center text-[11px] mb-1">
                <span className="text-slate-400 truncate">{cat}</span>
                <span className="font-mono font-bold text-white">{val}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1">
                <div
                  className={`h-full rounded-full transition-all ${
                    val >= 80 ? "bg-emerald-500" : val >= 50 ? "bg-amber-500" : "bg-rose-500"
                  }`}
                  style={{ width: `${val}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
