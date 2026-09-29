import React, { useEffect, useState } from "react";
import { History, AlertCircle, Layers, RefreshCw } from "lucide-react";
import { SecurityTimeline as SecurityTimelineData } from "../types";
import { getTimeline } from "../services/api";

interface SecurityTimelineProps {
  analysisId: string;
}

const severityColor = (sev: string) => {
  switch (sev) {
    case "Critical":
      return "text-rose-400 bg-rose-950/40 border-rose-500/40";
    case "High":
      return "text-orange-400 bg-orange-950/40 border-orange-500/40";
    case "Medium":
      return "text-amber-400 bg-amber-950/40 border-amber-500/40";
    default:
      return "text-cyan-400 bg-cyan-950/40 border-cyan-500/40";
  }
};

const scoreColor = (score: number) => {
  if (score >= 90) return "text-emerald-400 border-emerald-500/50 bg-emerald-500/10";
  if (score >= 70) return "text-cyan-400 border-cyan-500/50 bg-cyan-500/10";
  if (score >= 50) return "text-amber-400 border-amber-500/50 bg-amber-500/10";
  return "text-rose-400 border-rose-500/50 bg-rose-500/10";
};

export const SecurityTimeline: React.FC<SecurityTimelineProps> = ({ analysisId }) => {
  const [data, setData] = useState<SecurityTimelineData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getTimeline(analysisId)
      .then((d) => !cancelled && setData(d))
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setIsLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-violet-500/10 border border-violet-500/30 rounded-lg text-violet-400">
            <History className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Security Timeline</h2>
            <p className="text-xs text-slate-400">
              How this tunnel's configuration and behavior have changed across observed snapshots.
            </p>
          </div>
        </div>
        {data?.is_simulated && (
          <span className="text-[10px] font-mono uppercase px-2 py-0.5 bg-violet-500/10 text-violet-300 border border-violet-500/30 rounded-full">
            {data.simulation_label}
          </span>
        )}
      </div>

      {isLoading && (
        <div className="flex items-center space-x-2 text-xs text-slate-400 py-8 justify-center">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Loading tunnel history...</span>
        </div>
      )}

      {error && (
        <div className="text-xs text-rose-300 flex items-center space-x-2 py-4">
          <AlertCircle className="w-4 h-4" />
          <span>{error}</span>
        </div>
      )}

      {data && !isLoading && (
        <>
          {/* Snapshot chain */}
          <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 overflow-x-auto">
            <div className="flex items-stretch space-x-3 min-w-max">
              {data.snapshots.map((s, i) => (
                <React.Fragment key={s.analysis_id}>
                  <div
                    className={`w-40 shrink-0 p-3 rounded-lg border ${scoreColor(s.overall_score)} flex flex-col justify-between`}
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono uppercase opacity-80">
                      <span>{s.label}</span>
                      <span>{s.posture_grade}</span>
                    </div>
                    <div className="text-2xl font-bold font-mono my-1">{s.overall_score}</div>
                    <div className="text-[10px] font-mono truncate" title={s.encryption || undefined}>
                      {s.encryption || "Unknown cipher"}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-1 truncate">{s.filename}</div>
                  </div>
                  {i < data.snapshots.length - 1 && (
                    <div className="flex items-center text-slate-600 shrink-0">
                      <Layers className="w-4 h-4" />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Correlated sequences */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Correlated Event Sequences ({data.correlated_sequences.length})
            </h3>
            {data.correlated_sequences.length === 0 ? (
              <div className="text-[11px] text-slate-500 italic px-1">
                No temporally-correlated event clusters were found in this history.
              </div>
            ) : (
              data.correlated_sequences.map((seq) => (
                <div key={seq.sequence_id} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-amber-300">{seq.label}</span>
                    <span className="text-[10px] font-mono text-slate-500">{seq.events.length} events</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{seq.interpretation}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {seq.events.map((e) => (
                      <span
                        key={e.event_id}
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${severityColor(e.severity)}`}
                        title={e.evidence}
                      >
                        {e.event_type.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
};
