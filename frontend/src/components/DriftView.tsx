import React from "react";
import { GitCompare, AlertTriangle, CheckCircle2, ArrowRight } from "lucide-react";
import { ConfigurationDrift } from "../types";

interface DriftViewProps {
  drift: ConfigurationDrift;
}

export const DriftView: React.FC<DriftViewProps> = ({ drift }) => {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
            <GitCompare className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Configuration Drift & Regression Detection
            </h2>
            <p className="text-xs text-slate-400">
              Continuously comparing observed operational state against authorized enterprise baselines.
            </p>
          </div>
        </div>

        <span
          className={`text-[11px] font-mono px-2.5 py-1 rounded-full border font-bold ${
            drift.has_drift
              ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
              : "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
          }`}
        >
          {drift.has_drift ? "CONFIGURATION DRIFT DETECTED" : "BASELINE COMPLIANT"}
        </span>
      </div>

      {drift.has_drift ? (
        <div className="space-y-4">
          <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg flex items-center justify-between text-xs text-amber-200">
            <span>
              Baseline Target: <strong>{drift.baseline_name || "Enterprise High-Security Baseline"}</strong>
            </span>
            <span className="font-mono text-slate-400">
              Detected: {drift.drift_detected_at ? new Date(drift.drift_detected_at).toLocaleTimeString() : "Just now"}
            </span>
          </div>

          {/* Drift Table */}
          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Parameter</th>
                  <th className="py-2.5 px-3">Authorized Baseline</th>
                  <th className="py-2.5 px-3">Current Observed</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Security Implication</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {drift.changes.map((c, i) => (
                  <tr key={i} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-slate-200 font-sans font-bold">{c.parameter}</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-bold">{c.previous_value || "N/A"}</td>
                    <td className="py-2.5 px-3 text-rose-400 font-bold">{c.current_value || "N/A"}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded border font-bold ${
                          c.severity === "Critical"
                            ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                            : c.severity === "High"
                            ? "bg-orange-500/20 text-orange-300 border-orange-500/40"
                            : "bg-amber-500/20 text-amber-300 border-amber-500/40"
                        }`}
                      >
                        {c.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans text-[11px] leading-snug">
                      {c.security_implication}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="p-6 text-center space-y-2 bg-slate-950/40 rounded-xl border border-slate-800">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
          <h3 className="text-sm font-bold text-white">No Configuration Drift</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            The observed VPN parameters match the authorized golden security baseline. No unapproved cipher downgrades or protocol rollbacks detected.
          </p>
        </div>
      )}
    </div>
  );
};
