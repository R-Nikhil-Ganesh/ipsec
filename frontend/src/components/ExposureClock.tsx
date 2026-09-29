import React, { useEffect, useState } from "react";
import { Clock, ShieldCheck, ShieldAlert, Info, RefreshCw } from "lucide-react";
import { ExposureClock as ExposureClockData } from "../types";
import { getExposureClock } from "../services/api";

interface ExposureClockProps {
  analysisId: string;
}

export const ExposureClock: React.FC<ExposureClockProps> = ({ analysisId }) => {
  const [data, setData] = useState<ExposureClockData | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getExposureClock(analysisId)
      .then((d) => !cancelled && setData(d))
      .finally(() => !cancelled && setIsLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  const isDegraded = data?.security_state === "DEGRADED";

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
        <div className="p-1.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
          <Clock className="w-4 h-4" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">Security Exposure Clock</h2>
          <p className="text-xs text-slate-400">How long this tunnel has stayed in a degraded configuration state.</p>
        </div>
      </div>

      {isLoading || !data ? (
        <div className="flex items-center space-x-2 text-xs text-slate-400 py-8 justify-center">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Computing exposure window...</span>
        </div>
      ) : (
        <>
          <div
            className={`p-5 rounded-xl border flex items-center justify-between ${
              isDegraded
                ? "bg-rose-950/30 border-rose-500/50"
                : "bg-emerald-950/20 border-emerald-500/40"
            }`}
          >
            <div className="flex items-center space-x-3">
              {isDegraded ? (
                <ShieldAlert className="w-8 h-8 text-rose-400" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-400" />
              )}
              <div>
                <div
                  className={`text-xs font-bold uppercase tracking-widest ${
                    isDegraded ? "text-rose-300" : "text-emerald-300"
                  }`}
                >
                  {data.security_state}
                </div>
                <div className="text-2xl font-mono font-extrabold text-white">{data.duration_human}</div>
              </div>
            </div>
            <div className="text-right text-xs text-slate-400 space-y-0.5">
              <div>
                Score: <span className="font-mono text-slate-200">{data.risk_score_start ?? "—"}</span> →{" "}
                <span className="font-mono text-white font-bold">{data.risk_score_current}</span>
              </div>
              <div>
                Affected SAs: <span className="font-mono text-slate-200">{data.affected_sas}</span>
              </div>
              <div>
                Transitions: <span className="font-mono text-slate-200">{data.security_transitions}</span>
              </div>
            </div>
          </div>

          <div className="flex items-start space-x-2.5 px-3 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-[11px] text-slate-400">
            <Info className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
            <span>{data.disclaimer}</span>
          </div>
        </>
      )}
    </div>
  );
};
