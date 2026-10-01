import React from "react";
import { Zap, X, ShieldAlert, ShieldCheck, GitCompare, AlertTriangle, Cpu, History } from "lucide-react";
import { DemoSample } from "../types";

interface DemoSelectorProps {
  isOpen: boolean;
  onClose: () => void;
  samples: DemoSample[];
  onSelectSample: (sampleId: string) => void;
  isLoading: boolean;
}

export const DemoSelector: React.FC<DemoSelectorProps> = ({
  isOpen,
  onClose,
  samples,
  onSelectSample,
  isLoading,
}) => {
  if (!isOpen) return null;

  const getSampleIcon = (id: string) => {
    switch (id) {
      case "config-drift":
        return <GitCompare className="w-5 h-5 text-amber-400" />;
      case "weak-crypto":
        return <ShieldAlert className="w-5 h-5 text-rose-400" />;
      case "strong-vpn":
        return <ShieldCheck className="w-5 h-5 text-emerald-400" />;
      case "anomalous-vpn":
        return <AlertTriangle className="w-5 h-5 text-orange-400" />;
      case "legacy-vpn":
        return <Cpu className="w-5 h-5 text-red-500" />;
      case "temporal-evolution":
        return <History className="w-5 h-5 text-violet-400" />;
      default:
        return <Zap className="w-5 h-5 text-cyan-400" />;
    }
  };

  const getTagBadgeColor = (id: string) => {
    switch (id) {
      case "strong-vpn":
        return "bg-emerald-500/10 text-emerald-300 border-emerald-500/30";
      case "config-drift":
        return "bg-amber-500/10 text-amber-300 border-amber-500/30";
      case "weak-crypto":
      case "legacy-vpn":
        return "bg-rose-500/10 text-rose-300 border-rose-500/30";
      case "temporal-evolution":
        return "bg-violet-500/10 text-violet-300 border-violet-500/30";
      default:
        return "bg-cyan-500/10 text-cyan-300 border-cyan-500/30";
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/80">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                Current Configurations — Controlled Laboratory Datasets
              </h2>
              <p className="text-xs text-slate-400">
                Select a verified laboratory IPsec PCAP to test end-to-end detection, drift, or attack graphs.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* List of samples */}
        <div className="p-6 space-y-3 max-h-[70vh] overflow-y-auto">
          {samples.map((s) => (
            <div
              key={s.id}
              onClick={() => !isLoading && onSelectSample(s.id)}
              className="group p-4 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 hover:border-cyan-500/50 rounded-xl cursor-pointer transition-all flex items-start space-x-4"
            >
              <div className="p-2.5 bg-slate-900/80 rounded-lg border border-slate-700/80 group-hover:scale-105 transition-transform">
                {getSampleIcon(s.id)}
              </div>
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-1">
                  <h3 className="text-sm font-semibold text-white group-hover:text-cyan-300 transition-colors">
                    {s.name}
                  </h3>
                  <span
                    className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 border rounded-full ${getTagBadgeColor(
                      s.id
                    )}`}
                  >
                    {s.tag}
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {s.description}
                </p>
                <div className="mt-2 text-[11px] font-mono text-slate-500 flex items-center space-x-2">
                  <span>File: {s.pcap}</span>
                  <span>•</span>
                  <span className="text-cyan-400 font-semibold">Click to Load & Analyze</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
          <span>Datasets: Controlled laboratory environments (RFC 7296 & RFC 4303)</span>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-medium transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
