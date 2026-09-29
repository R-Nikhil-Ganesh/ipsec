import React from "react";
import { EyeOff, AlertTriangle, ShieldCheck, CheckCircle2, Info } from "lucide-react";
import { MetadataPrivacyAnalysis } from "../types";

interface MetadataPrivacyViewProps {
  privacy: MetadataPrivacyAnalysis;
}

export const MetadataPrivacyView: React.FC<MetadataPrivacyViewProps> = ({ privacy }) => {
  const score = privacy.metadata_exposure_score;

  const getScoreColor = () => {
    if (score >= 70) return "text-rose-400 bg-rose-500/10 border-rose-500/30";
    if (score >= 45) return "text-amber-400 bg-amber-500/10 border-amber-500/30";
    return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-purple-500/10 border border-purple-500/30 rounded-lg text-purple-400">
            <EyeOff className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Encrypted Traffic Privacy Analysis (Side-Channel Exposure)
            </h2>
            <p className="text-xs text-slate-400">
              Assessing passive traffic leakage: packet length variance, timing periodicity, and burst signatures.
            </p>
          </div>
        </div>

        <span className="text-[11px] font-mono text-purple-300 bg-purple-950/60 border border-purple-800/80 px-2.5 py-1 rounded-full">
          RFC 4303 TFC Compliance
        </span>
      </div>

      {/* Exposure Score Callout */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
        <div className={`p-4 rounded-xl border ${getScoreColor()} flex flex-col justify-between`}>
          <span className="text-[11px] uppercase font-mono tracking-wider font-semibold">
            Metadata Exposure Score
          </span>
          <div className="my-2 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono">{score}</span>
            <span className="text-xs font-mono opacity-80">/ 100</span>
          </div>
          <span className="text-xs font-bold uppercase">{privacy.risk_level}</span>
        </div>

        {/* Feature stats */}
        <div className="col-span-2 p-4 bg-slate-950/80 rounded-xl border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Length Variance</span>
            <span className="font-mono text-xs font-bold text-white">{privacy.packet_size_variability}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Timing Pattern</span>
            <span className="font-mono text-xs font-bold text-white">{privacy.timing_regularity}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Directionality</span>
            <span className="font-mono text-xs font-bold text-white">{privacy.directionality_ratio} ratio</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Burst Index</span>
            <span className="font-mono text-xs font-bold text-white">{privacy.burstiness_index}</span>
          </div>
        </div>
      </div>

      {/* Side-Channel Risk Factors Table */}
      <div className="space-y-2">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Side-Channel Leakage Factors
        </h3>
        <div className="space-y-2">
          {privacy.factors.map((f, i) => (
            <div
              key={i}
              className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 flex items-start justify-between gap-3 text-xs"
            >
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-slate-200">{f.name}</span>
                  <span className="font-mono text-[11px] text-cyan-400">[{f.value}]</span>
                </div>
                <p className="text-slate-400 mt-1 leading-relaxed text-[11px]">{f.explanation}</p>
              </div>
              <span
                className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border shrink-0 font-bold ${
                  f.impact === "High Risk"
                    ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
                    : f.impact === "Moderate Risk"
                    ? "bg-amber-500/10 text-amber-300 border-amber-500/30"
                    : "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                }`}
              >
                {f.impact}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Privacy Mitigation Guidance */}
      <div className="p-3 bg-purple-950/20 border border-purple-500/30 rounded-lg text-xs text-purple-200/90 leading-relaxed">
        <strong>Privacy Hardening Recommendation:</strong> {privacy.privacy_recommendation}
      </div>
    </div>
  );
};
