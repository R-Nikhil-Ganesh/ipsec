import React from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  Radio,
  AlertTriangle,
  GitCompare,
  ArrowRight,
  Clock,
  Layers,
} from "lucide-react";
import { VPNFingerprint, RiskScoreBreakdown, ConfigurationDrift, AnomalyFinding } from "../types";

interface VPNOverviewCardsProps {
  fingerprint: VPNFingerprint;
  riskScore: RiskScoreBreakdown;
  drift: ConfigurationDrift;
  anomalies: AnomalyFinding[];
  onOpenWhatIf: () => void;
  onOpenDrift: () => void;
}

export const VPNOverviewCards: React.FC<VPNOverviewCardsProps> = ({
  fingerprint,
  riskScore,
  drift,
  anomalies,
  onOpenWhatIf,
  onOpenDrift,
}) => {
  const score = riskScore.overall_score;
  const grade = riskScore.posture_grade;

  const getScoreTheme = () => {
    if (score >= 90) return { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", bar: "bg-emerald-500" };
    if (score >= 70) return { text: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30", bar: "bg-cyan-500" };
    if (score >= 50) return { text: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", bar: "bg-amber-500" };
    return { text: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/30", bar: "bg-rose-500" };
  };

  const theme = getScoreTheme();
  const detectedAnomalies = anomalies.filter((a) => a.anomaly_detected);

  return (
    <div className="space-y-4">
      {/* ⚠️ CONFIGURATION DRIFT ALERT BANNER (If Drift Detected) */}
      {drift.has_drift && (
        <div className="p-4 bg-amber-950/40 border border-amber-500/60 rounded-xl shadow-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 animate-in fade-in duration-300">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-amber-500/20 border border-amber-500/40 rounded-lg text-amber-400">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-amber-300 uppercase tracking-wide">
                  Configuration Drift Detected
                </span>
                <span className="text-[10px] px-2 py-0.5 bg-amber-500/20 text-amber-200 border border-amber-500/30 rounded-full font-bold">
                  {drift.changes.length} Regressions
                </span>
              </div>
              <p className="text-xs text-amber-200/80 mt-0.5">
                Current tunnel settings have silently regressed against established baseline ({drift.baseline_name || "Enterprise Standard"}).
              </p>
            </div>
          </div>
          <button
            onClick={onOpenDrift}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs rounded-lg transition-colors shadow-md shadow-amber-500/20"
          >
            <span>Inspect Drift Diff</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* TOP SOC METRIC CARDS GRID */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* Card 1: Security Score */}
        <div className={`col-span-2 p-4 rounded-xl border ${theme.border} ${theme.bg} backdrop-blur-sm flex flex-col justify-between shadow-lg`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className={`w-5 h-5 ${theme.text}`} />
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Security Posture
              </span>
            </div>
            <span className={`text-xs px-2.5 py-0.5 rounded-full font-extrabold border ${theme.border} ${theme.text}`}>
              Grade {grade}
            </span>
          </div>

          <div className="my-2 flex items-baseline space-x-2">
            <span className={`text-4xl font-extrabold font-mono tracking-tight ${theme.text}`}>
              {score}
            </span>
            <span className="text-sm text-slate-400 font-mono">/ 100</span>
            <span className="text-xs text-slate-400 ml-auto">
              {riskScore.total_penalty > 0 ? `-${riskScore.total_penalty} pts penalty` : "Compliant"}
            </span>
          </div>

          <div>
            <div className="w-full bg-slate-800/80 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full ${theme.bar} transition-all duration-700`}
                style={{ width: `${score}%` }}
              ></div>
            </div>
            <div className="flex justify-between items-center mt-2 text-[11px] text-slate-400">
              <span>NIST SP 800-77 Rev. 1</span>
              <button
                onClick={onOpenWhatIf}
                className="text-cyan-400 hover:text-cyan-300 font-medium underline flex items-center space-x-1"
              >
                <span>Simulate Hardening</span>
              </button>
            </div>
          </div>
        </div>

        {/* Card 2: Protocol & Mode */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Mode</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-white">
              {fingerprint.mode || "Tunnel"} Mode
            </div>
            <div className="flex items-center space-x-1 mt-0.5">
              <span className="text-[10px] px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded border border-slate-700 font-mono">
                {fingerprint.mode_status}
              </span>
              <span className="text-[10px] text-slate-400">
                ({Math.round(fingerprint.confidence * 100)}% conf)
              </span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {fingerprint.ip_version || "IPv4"} Encapsulation
          </div>
        </div>

        {/* Card 3: IKE Version */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">IKE Version</span>
            <Radio className="w-4 h-4 text-slate-400" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-white">
              {fingerprint.ike_version || "Not In Trace"}
            </div>
            <div className="flex items-center space-x-1 mt-0.5">
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${
                  fingerprint.ike_version === "IKEv1"
                    ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
                    : "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                }`}
              >
                {fingerprint.ike_version_status}
              </span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {fingerprint.ike_version === "IKEv1" ? "Deprecated (RFC 9395)" : "Standard RFC 7296"}
          </div>
        </div>

        {/* Card 4: Cipher Suite */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Encryption</span>
            <Lock className="w-4 h-4 text-slate-400" />
          </div>
          <div className="my-2">
            <div className="text-base font-bold text-white truncate" title={fingerprint.encryption || "Unknown"}>
              {fingerprint.encryption || "Unknown"}
            </div>
            <div className="flex items-center space-x-1 mt-0.5">
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${
                  (fingerprint.encryption || "").includes("DES")
                    ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
                    : "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                }`}
              >
                {fingerprint.encryption_status}
              </span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {fingerprint.integrity || "AEAD Combined"}
          </div>
        </div>

        {/* Card 5: Diffie-Hellman & PFS */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Key Exchange</span>
            <Key className="w-4 h-4 text-slate-400" />
          </div>
          <div className="my-2">
            <div className="text-base font-bold text-white truncate" title={fingerprint.dh_group_name || `Group ${fingerprint.dh_group}`}>
              {fingerprint.dh_group_name ? fingerprint.dh_group_name.split(" ")[0] : `Group ${fingerprint.dh_group || "Unknown"}`}
            </div>
            <div className="flex items-center space-x-1 mt-0.5">
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${
                  fingerprint.pfs === true
                    ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                    : "bg-rose-500/10 text-rose-300 border-rose-500/30"
                }`}
              >
                PFS: {fingerprint.pfs ? "Active" : "Disabled"}
              </span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            Replay: {fingerprint.replay_protection ? "Protected" : "Warning"}
          </div>
        </div>

        {/* Card 6: Anomalies / Health */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Anomalies</span>
            <AlertTriangle className={`w-4 h-4 ${detectedAnomalies.length > 0 ? "text-orange-400 animate-pulse" : "text-slate-400"}`} />
          </div>
          <div className="my-2">
            <div className={`text-2xl font-bold font-mono ${detectedAnomalies.length > 0 ? "text-orange-400" : "text-emerald-400"}`}>
              {detectedAnomalies.length}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">
              Isolation Forest model
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {detectedAnomalies.length > 0 ? `${detectedAnomalies[0].anomaly_type.slice(0, 16)}...` : "Baseline Nominal"}
          </div>
        </div>
      </div>
    </div>
  );
};
