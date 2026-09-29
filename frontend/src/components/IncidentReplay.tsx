import React, { useEffect, useRef, useState } from "react";
import { PlayCircle, PauseCircle, SkipBack, RefreshCw, Clock } from "lucide-react";
import { IncidentReplay as IncidentReplayData } from "../types";
import { replayIncident } from "../services/api";

interface IncidentReplayProps {
  analysisId: string;
}

const scoreColor = (score: number) => {
  if (score >= 90) return "text-emerald-400";
  if (score >= 70) return "text-cyan-400";
  if (score >= 50) return "text-amber-400";
  return "text-rose-400";
};

export const IncidentReplay: React.FC<IncidentReplayProps> = ({ analysisId }) => {
  const [data, setData] = useState<IncidentReplayData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [frameIndex, setFrameIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    replayIncident(analysisId)
      .then((d) => {
        if (cancelled) return;
        setData(d);
        setFrameIndex(0);
      })
      .finally(() => !cancelled && setIsLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  useEffect(() => {
    if (!isPlaying || !data) return;
    intervalRef.current = setInterval(() => {
      setFrameIndex((prev) => {
        if (prev >= data.frames.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1500);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isPlaying, data]);

  if (isLoading || !data) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl flex items-center justify-center py-12">
        <RefreshCw className="w-4 h-4 animate-spin text-slate-400 mr-2" />
        <span className="text-xs text-slate-400">Building incident replay...</span>
      </div>
    );
  }

  const frame = data.frames[frameIndex];

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Clock className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Incident Replay</h2>
            <p className="text-xs text-slate-400">Step through this tunnel's security evolution, frame by frame.</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => {
              setIsPlaying(false);
              setFrameIndex(0);
            }}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            title="Restart"
          >
            <SkipBack className="w-4 h-4" />
          </button>
          <button
            onClick={() => setIsPlaying((p) => !p)}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg"
          >
            {isPlaying ? <PauseCircle className="w-4 h-4" /> : <PlayCircle className="w-4 h-4" />}
            <span>{isPlaying ? "Pause" : "Replay Security Evolution"}</span>
          </button>
        </div>
      </div>

      {/* Frame scrubber */}
      <div className="flex items-center space-x-1.5">
        {data.frames.map((f, i) => (
          <button
            key={f.index}
            onClick={() => {
              setIsPlaying(false);
              setFrameIndex(i);
            }}
            className={`flex-1 h-2 rounded-full transition-colors ${
              i <= frameIndex ? "bg-cyan-500" : "bg-slate-800"
            }`}
            title={f.label}
          />
        ))}
      </div>

      {/* Current frame state */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-center">
          <div className="text-[10px] uppercase text-slate-400">Frame</div>
          <div className="text-lg font-mono font-bold text-white">{frame.label}</div>
          <div className="text-[10px] text-slate-500 font-mono truncate">{frame.snapshot.filename}</div>
        </div>
        <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-center">
          <div className="text-[10px] uppercase text-slate-400">Risk Score</div>
          <div className={`text-lg font-mono font-bold ${scoreColor(frame.snapshot.overall_score)}`}>
            {frame.snapshot.overall_score}
          </div>
          <div className="text-[10px] text-slate-500">{frame.snapshot.posture_grade}</div>
        </div>
        <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-center">
          <div className="text-[10px] uppercase text-slate-400">Exposure</div>
          <div
            className={`text-sm font-bold ${
              frame.exposure.security_state === "DEGRADED" ? "text-rose-400" : "text-emerald-400"
            }`}
          >
            {frame.exposure.security_state}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">{frame.exposure.duration_human}</div>
        </div>
        <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-center">
          <div className="text-[10px] uppercase text-slate-400">Forecast</div>
          <div className="text-sm font-bold text-amber-300">{frame.forecast.trend}</div>
          <div className="text-[10px] text-slate-500">{Math.round(frame.forecast.confidence * 100)}% conf.</div>
        </div>
      </div>

      {/* Events introduced at this frame */}
      <div>
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5">
          Events at {frame.label} ({frame.events_at_this_point.length})
        </h3>
        {frame.events_at_this_point.length === 0 ? (
          <div className="text-[11px] text-slate-500 italic">No configuration or behavioral changes at this stage.</div>
        ) : (
          <div className="space-y-1">
            {frame.events_at_this_point.map((e) => (
              <div
                key={e.event_id}
                className="text-[11px] px-2.5 py-1.5 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between text-slate-300"
              >
                <span>{e.evidence}</span>
                <span className="font-mono text-[10px] text-slate-500 shrink-0 ml-2">{e.severity}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
