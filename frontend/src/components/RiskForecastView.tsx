import React, { useEffect, useState } from "react";
import { TrendingUp, TrendingDown, Minus, HelpCircle, Info, RefreshCw, GitBranch } from "lucide-react";
import { RiskForecast, SecurityTimeline, RiskPathGraph } from "../types";
import { getRiskForecast, getTimeline, getTemporalGraph } from "../services/api";

interface RiskForecastViewProps {
  analysisId: string;
}

const trendMeta = (trend: string) => {
  switch (trend) {
    case "ESCALATING":
      return { icon: TrendingUp, color: "text-rose-400", bg: "bg-rose-950/30 border-rose-500/40" };
    case "IMPROVING":
      return { icon: TrendingDown, color: "text-emerald-400", bg: "bg-emerald-950/20 border-emerald-500/40" };
    case "STABLE":
      return { icon: Minus, color: "text-cyan-400", bg: "bg-cyan-950/20 border-cyan-500/40" };
    default:
      return { icon: HelpCircle, color: "text-slate-400", bg: "bg-slate-900/60 border-slate-700" };
  }
};

const nodeStateColor = (state?: string | null) => {
  if (state === "Requires investigation") return "border-amber-500/70 bg-amber-950/30 text-amber-300";
  if (state === "Potential consequence") return "border-orange-500/70 bg-orange-950/30 text-orange-300";
  return "border-cyan-500/60 bg-cyan-950/30 text-cyan-300";
};

export const RiskForecastView: React.FC<RiskForecastViewProps> = ({ analysisId }) => {
  const [forecast, setForecast] = useState<RiskForecast | null>(null);
  const [timeline, setTimeline] = useState<SecurityTimeline | null>(null);
  const [graph, setGraph] = useState<RiskPathGraph | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    Promise.all([getRiskForecast(analysisId), getTimeline(analysisId), getTemporalGraph(analysisId)])
      .then(([f, t, g]) => {
        if (cancelled) return;
        setForecast(f);
        setTimeline(t);
        setGraph(g);
      })
      .finally(() => !cancelled && setIsLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  if (isLoading || !forecast) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl flex items-center justify-center py-12">
        <RefreshCw className="w-4 h-4 animate-spin text-slate-400 mr-2" />
        <span className="text-xs text-slate-400">Computing risk trajectory...</span>
      </div>
    );
  }

  const meta = trendMeta(forecast.trend);
  const TrendIcon = meta.icon;
  const scores = timeline?.snapshots.map((s) => s.overall_score) || [];
  const maxScore = Math.max(100, ...scores);

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
      <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
        <div className="p-1.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400">
          <TrendIcon className="w-4 h-4" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">Explainable Risk Forecast</h2>
          <p className="text-xs text-slate-400">A deterministic, rule-based projection — never a black-box guess.</p>
        </div>
      </div>

      {/* Risk trajectory bars */}
      {scores.length > 0 && (
        <div className="space-y-1.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Risk Trajectory</h3>
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 overflow-x-auto">
            <div className="flex items-end space-x-2 h-24 min-w-max">
              {timeline!.snapshots.map((s) => (
                <div key={s.analysis_id} className="w-9 shrink-0 flex flex-col items-center justify-end h-full">
                  <span className="text-[10px] font-mono text-slate-400 mb-1">{s.overall_score}</span>
                  <div
                    className={`w-full rounded-t ${
                      s.overall_score >= 90
                        ? "bg-emerald-500"
                        : s.overall_score >= 70
                        ? "bg-cyan-500"
                        : s.overall_score >= 50
                        ? "bg-amber-500"
                        : "bg-rose-500"
                    }`}
                    style={{ height: `${Math.max(4, (s.overall_score / maxScore) * 100)}%` }}
                  />
                  <span className="text-[10px] font-mono text-slate-500 mt-1">{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Forecast card */}
      <div className={`p-4 rounded-xl border ${meta.bg} space-y-2`}>
        <div className="flex items-center justify-between">
          <span className={`text-sm font-extrabold uppercase tracking-wide ${meta.color}`}>
            Trend: {forecast.trend}
          </span>
          <span className="text-xs font-mono text-slate-300">
            Confidence: <strong>{Math.round(forecast.confidence * 100)}%</strong>
          </span>
        </div>
        {forecast.risk_factors.length > 0 && (
          <div>
            <div className="text-[11px] text-slate-400 mb-1">Drivers:</div>
            <ul className="text-xs text-slate-200 space-y-0.5 list-disc list-inside">
              {forecast.risk_factors.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="text-[11px] text-slate-400">Forecast window: {forecast.forecast_window.replace(/_/g, " ")}</div>
      </div>

      <div className="flex items-start space-x-2.5 px-3 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-[11px] text-slate-400">
        <Info className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
        <span>{forecast.disclaimer}</span>
      </div>

      {/* Temporal / predicted risk path */}
      {graph && graph.nodes.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <GitBranch className="w-3.5 h-3.5" />
            <span>Temporal Attack / Risk Path</span>
          </h3>
          <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 overflow-x-auto">
            <div className="flex items-center space-x-3 min-w-max">
              {graph.nodes.map((n, i) => (
                <React.Fragment key={n.id}>
                  <div
                    className={`p-2.5 rounded-lg border max-w-[180px] text-center shrink-0 ${nodeStateColor(n.state)}`}
                    title={n.details}
                  >
                    <div className="text-[9px] uppercase font-mono opacity-80">{n.state || "Observed"}</div>
                    <div className="text-[11px] font-bold leading-snug">{n.label}</div>
                  </div>
                  {i < graph.nodes.length - 1 && <span className="text-slate-600 shrink-0">→</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
