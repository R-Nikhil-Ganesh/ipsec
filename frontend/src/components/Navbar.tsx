import React from "react";
import { Shield, Activity, FileText, Zap, Upload, RefreshCw } from "lucide-react";

interface NavbarProps {
  currentFilename?: string;
  onOpenUpload: () => void;
  onOpenDemoLab: () => void;
  onOpenReports: () => void;
  isLoading: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentFilename,
  onOpenUpload,
  onOpenDemoLab,
  onOpenReports,
  isLoading,
}) => {
  return (
    <header className="bg-slate-900/90 backdrop-blur-md border-b border-slate-800 sticky top-0 z-50 px-6 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-white tracking-wide">
                IPsec <span className="text-cyan-400">Sentinel</span>
              </span>
              <span className="text-[10px] uppercase font-mono tracking-widest px-2 py-0.5 bg-slate-800 text-slate-300 border border-slate-700 rounded">
                v1.0 MVP
              </span>
            </div>
            <p className="text-xs text-slate-400">
              AI-Powered IPsec VPN Security Intelligence & Digital Twin Platform
            </p>
          </div>
        </div>

        {/* Status & Active Target */}
        <div className="hidden md:flex items-center space-x-4">
          <div className="flex items-center space-x-2 px-3 py-1 bg-slate-800/60 border border-slate-700/60 rounded-full text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 radar-live"></span>
            <span>Sensor: <strong>Active (Scapy Engine)</strong></span>
          </div>

          {currentFilename && (
            <div className="flex items-center space-x-2 px-3 py-1 bg-cyan-950/40 border border-cyan-800/50 rounded-md text-xs text-cyan-200 font-mono">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target: <strong>{currentFilename}</strong></span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          <button
            onClick={onOpenDemoLab}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-500/10 border border-amber-500/30 hover:bg-amber-500/20 text-amber-300 text-xs font-semibold rounded-lg transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Demo Lab</span>
          </button>

          <button
            onClick={onOpenUpload}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg transition-all shadow-md shadow-cyan-600/20 disabled:opacity-50"
          >
            {isLoading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Upload className="w-3.5 h-3.5" />
            )}
            <span>Analyze PCAP</span>
          </button>

          {currentFilename && (
            <button
              onClick={onOpenReports}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-all"
            >
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span>Reports</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
