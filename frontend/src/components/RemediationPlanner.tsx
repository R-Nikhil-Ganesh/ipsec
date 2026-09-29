import React, { useEffect, useState } from "react";
import {
  Wrench,
  CheckCircle2,
  ArrowUpRight,
  RefreshCw,
  Play,
  Terminal,
  Copy,
  Check,
} from "lucide-react";
import { RemediationComparison, WhatIfResult } from "../types";
import { getRemediationPlans, simulateRemediationPlan } from "../services/api";

interface RemediationPlannerProps {
  analysisId: string;
}

export const RemediationPlanner: React.FC<RemediationPlannerProps> = ({ analysisId }) => {
  const [data, setData] = useState<RemediationComparison | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [applying, setApplying] = useState<string | null>(null);
  const [appliedResults, setAppliedResults] = useState<Record<string, WhatIfResult>>({});
  const [applyError, setApplyError] = useState<string | null>(null);
  const [copiedPlanId, setCopiedPlanId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getRemediationPlans(analysisId)
      .then((d) => !cancelled && setData(d))
      .finally(() => !cancelled && setIsLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  const handleApply = async (planId: string) => {
    setApplying(planId);
    setApplyError(null);
    try {
      const result = await simulateRemediationPlan(analysisId, planId);
      setAppliedResults((prev) => ({ ...prev, [planId]: result }));
    } catch (err: any) {
      setApplyError(err?.message || "Simulation failed.");
    } finally {
      setApplying(null);
    }
  };

  const copySnippet = (planId: string, snippet: string) => {
    navigator.clipboard.writeText(snippet);
    setCopiedPlanId(planId);
    setTimeout(() => setCopiedPlanId((prev) => (prev === planId ? null : prev)), 2000);
  };

  if (isLoading || !data) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl flex items-center justify-center py-12">
        <RefreshCw className="w-4 h-4 animate-spin text-slate-400 mr-2" />
        <span className="text-xs text-slate-400">Generating remediation plans...</span>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400">
            <Wrench className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Automated Remediation Planner</h2>
            <p className="text-xs text-slate-400">
              Candidate hardening plans, each scored by the same What-If simulator used elsewhere in this app.
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] uppercase text-slate-400">Current</div>
          <div className="text-lg font-mono font-bold text-slate-200">
            {data.current_score} <span className="text-xs text-slate-500">({data.current_grade})</span>
          </div>
        </div>
      </div>

      {applyError && (
        <div className="text-xs text-rose-300 bg-rose-950/30 border border-rose-500/40 rounded-lg px-3 py-2">
          {applyError}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-start">
        {data.plans.map((plan, i) => {
          const applied = appliedResults[plan.plan_id];
          const activeResult = applied || plan.whatif_result;
          const projected = activeResult.projected_score;
          const grade = activeResult.projected_grade;
          return (
            <div
              key={plan.plan_id}
              className={`p-4 rounded-xl border space-y-3 flex flex-col ${
                i === 0
                  ? "border-emerald-500/50 bg-emerald-950/10"
                  : "border-slate-800 bg-slate-950/60"
              }`}
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">{plan.label}</span>
                  {i === 0 && (
                    <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 bg-emerald-500/20 text-emerald-300 rounded-full">
                      Best
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{plan.problem_summary}</p>
              </div>

              <div className="flex items-center justify-center space-x-2 py-2 bg-slate-900/60 rounded-lg border border-slate-800/80">
                <span className="text-lg font-mono font-bold text-slate-400">{data.current_score}</span>
                <ArrowUpRight className="w-4 h-4 text-emerald-400" />
                <span className="text-2xl font-mono font-extrabold text-emerald-400">{projected}</span>
                <span className="text-[10px] text-slate-500">({grade})</span>
              </div>

              <div className="space-y-1 text-[11px] text-slate-300">
                {plan.changes.map((c) => (
                  <div key={c.parameter} className="flex items-center justify-between font-mono">
                    <span className="text-slate-500">{c.parameter}</span>
                    <span className="truncate max-w-[130px]">
                      {c.from_value || "—"} → <span className="text-emerald-300">{c.to_value}</span>
                    </span>
                  </div>
                ))}
              </div>

              <div className="flex items-center space-x-1.5 text-[11px] text-emerald-300">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{plan.findings_resolved} findings resolved</span>
              </div>
              <div className="text-[11px] text-slate-400">
                {plan.graph_nodes_removed} risk-path node(s) / {plan.graph_edges_removed} edge(s) eliminated
              </div>

              <button
                onClick={() => handleApply(plan.plan_id)}
                disabled={applying === plan.plan_id}
                className={`flex items-center justify-center space-x-1.5 py-1.5 text-xs font-bold rounded-lg transition-colors disabled:opacity-50 ${
                  applied
                    ? "bg-emerald-600/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-600/30"
                    : "bg-cyan-600 hover:bg-cyan-500 text-white"
                }`}
              >
                {applying === plan.plan_id ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : applied ? (
                  <Check className="w-3.5 h-3.5" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                <span>{applied ? "Simulated — Re-run" : "Simulate Remediation"}</span>
              </button>

              {/* Revealed only after the plan has actually been run through the simulator */}
              {applied && (
                <div className="pt-3 mt-1 border-t border-slate-800 space-y-2 animate-in fade-in duration-200">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-slate-300 flex items-center space-x-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>strongSwan Patch</span>
                    </span>
                    <button
                      onClick={() => copySnippet(plan.plan_id, applied.config_snippet)}
                      className="flex items-center space-x-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
                    >
                      {copiedPlanId === plan.plan_id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-2.5 bg-slate-950 font-mono text-[10px] text-cyan-300 rounded-lg border border-slate-800 overflow-x-auto max-h-32">
                    {applied.config_snippet}
                  </pre>
                  {applied.hardening_guidance.length > 0 && (
                    <ul className="text-[11px] text-slate-400 space-y-1 list-disc list-inside">
                      {applied.hardening_guidance.map((g) => (
                        <li key={g}>{g}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
