import React from "react";
import { Activity, ShieldAlert, Cpu, BarChart2, Info } from "lucide-react";
import { TrafficClassification } from "../types";

interface EncryptedTrafficViewProps {
  traffic: TrafficClassification;
}

export const EncryptedTrafficView: React.FC<EncryptedTrafficViewProps> = ({ traffic }) => {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Encrypted Traffic Flow Classification
            </h2>
            <p className="text-xs text-slate-400">
              Inferring tunneled application behavior without decrypting ciphertext payloads.
            </p>
          </div>
        </div>

        <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2.5 py-1 rounded-full">
          Metadata-Based ML
        </span>
      </div>

      {/* Primary Classification Callout */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Prediction Card */}
        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 flex flex-col justify-between">
          <span className="text-[11px] uppercase font-mono text-slate-400">Inferred Application</span>
          <div className="my-2">
            <div className="text-xl font-bold text-emerald-400">{traffic.traffic_type}</div>
            <div className="text-xs text-slate-300 font-mono mt-1">
              Confidence: <strong>{Math.round(traffic.confidence * 100)}%</strong>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 leading-snug">
            Basis: <span className="text-slate-300">{traffic.basis}</span>
          </div>
        </div>

        {/* Flow Dynamics Statistics */}
        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Packets In Flow</span>
            <span className="font-mono text-base font-bold text-white">{traffic.packet_count}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Flow Bytes</span>
            <span className="font-mono text-base font-bold text-white">{(traffic.byte_count / 1024).toFixed(1)} KB</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Avg Packet Size</span>
            <span className="font-mono text-base font-bold text-white">{traffic.avg_packet_size} B</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Mean IAT</span>
            <span className="font-mono text-base font-bold text-white">{traffic.inter_arrival_mean_ms} ms</span>
          </div>
        </div>
      </div>

      {/* Class Probabilities Distribution */}
      {traffic.class_probabilities && Object.keys(traffic.class_probabilities).length > 0 && (
        <div className="space-y-2 pt-1">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Model Softmax Class Probabilities
          </h3>
          <div className="space-y-1.5">
            {Object.entries(traffic.class_probabilities).map(([cls, prob]) => (
              <div key={cls} className="space-y-0.5">
                <div className="flex justify-between text-xs text-slate-300">
                  <span className="font-medium">{cls}</span>
                  <span className="font-mono font-bold text-cyan-400">{Math.round(prob * 100)}%</span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 rounded-full transition-all duration-500"
                    style={{ width: `${Math.round(prob * 100)}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Mandatory Disclaimer Box (Section 9 Requirement) */}
      <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg flex items-center space-x-2 text-xs text-amber-300">
        <Info className="w-4 h-4 text-amber-400 shrink-0" />
        <span>
          <strong>Ethical & Technical Disclaimer:</strong> {traffic.disclaimer}
        </span>
      </div>
    </div>
  );
};
