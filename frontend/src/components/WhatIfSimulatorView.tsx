import React, { useState, useEffect } from "react";
import { Sliders, ArrowUpRight, CheckCircle2, AlertCircle, Terminal, Copy, Check, RefreshCw } from "lucide-react";
import { VPNFingerprint, WhatIfRequest, WhatIfResult } from "../types";
import { simulateHardening } from "../services/api";

interface WhatIfSimulatorViewProps {
  currentFingerprint: VPNFingerprint;
  analysisId?: string;
}

export const WhatIfSimulatorView: React.FC<WhatIfSimulatorViewProps> = ({
  currentFingerprint,
  analysisId,
}) => {
  const [ikeVer, setIkeVer] = useState<string>(currentFingerprint.ike_version || "IKEv2");
  const [encryption, setEncryption] = useState<string>("AES-256-GCM");
  const [dhGroup, setDhGroup] = useState<string>("19");
  const [pfs, setPfs] = useState<boolean>(true);
  const [replay, setReplay] = useState<boolean>(true);
  const [lifetime, setLifetime] = useState<number>(3600);

  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);

  // Run simulation whenever hardening parameters change
  useEffect(() => {
    let isCancelled = false;

    const runSim = async () => {
      setIsSimulating(true);
      try {
        const req: WhatIfRequest = {
          ike_version: ikeVer,
          encryption: encryption,
          dh_group: dhGroup,
          pfs: pfs,
          replay_protection: replay,
          sa_lifetime: lifetime,
        };
        const simRes = await simulateHardening(req, analysisId);
        if (!isCancelled) {
          setResult(simRes);
        }
      } catch (err) {
        console.error("Simulation error", err);
      } finally {
        if (!isCancelled) setIsSimulating(false);
      }
    };

    runSim();
    return () => {
      isCancelled = true;
    };
  }, [ikeVer, encryption, dhGroup, pfs, replay, lifetime, analysisId]);

  const copyPatch = () => {
    if (!result?.config_snippet) return;
    navigator.clipboard.writeText(result.config_snippet);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Sliders className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              What-If Hardening Simulator
            </h2>
            <p className="text-xs text-slate-400">
              Model proposed configuration enhancements and project resulting security posture in real-time.
            </p>
          </div>
        </div>

        <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800/80 px-2.5 py-1 rounded-full">
          Signature Capability
        </span>
      </div>

      {/* Simulator Grid: Interactive Controls on Left, Projected Posture on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Controls Column (5 cols) */}
        <div className="lg:col-span-5 space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
            Proposed Target Parameters
          </h3>

          {/* IKE Version */}
          <div>
            <label className="text-[11px] text-slate-300 font-semibold block mb-1">IKE Protocol Version</label>
            <div className="grid grid-cols-2 gap-2">
              {["IKEv2", "IKEv1"].map((v) => (
                <button
                  key={v}
                  onClick={() => setIkeVer(v)}
                  className={`py-1.5 px-3 text-xs rounded-lg font-medium border transition-colors ${
                    ikeVer === v
                      ? "bg-cyan-600/30 text-cyan-300 border-cyan-500"
                      : "bg-slate-900 hover:bg-slate-800 text-slate-400 border-slate-800"
                  }`}
                >
                  {v} {v === "IKEv2" ? "(Preferred)" : "(Legacy)"}
                </button>
              ))}
            </div>
          </div>

          {/* Encryption Cipher */}
          <div>
            <label className="text-[11px] text-slate-300 font-semibold block mb-1">Encryption Algorithm</label>
            <select
              value={encryption}
              onChange={(e) => setEncryption(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg py-1.5 px-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="AES-256-GCM">AES-256-GCM (Modern AEAD / Preferred)</option>
              <option value="AES-128-GCM">AES-128-GCM (Fast AEAD)</option>
              <option value="CHACHA20-POLY1305">ChaCha20-Poly1305 (AEAD Stream)</option>
              <option value="AES-128-CBC">AES-128-CBC (Legacy Block Mode)</option>
              <option value="3DES-CBC">3DES-CBC (Sweet32 Vulnerable)</option>
              <option value="DES-CBC">DES-CBC (Broken 56-bit)</option>
            </select>
          </div>

          {/* Diffie-Hellman Group */}
          <div>
            <label className="text-[11px] text-slate-300 font-semibold block mb-1">Diffie-Hellman Group</label>
            <select
              value={dhGroup}
              onChange={(e) => setDhGroup(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg py-1.5 px-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="19">Group 19 - NIST ECP-256 (High Security / Preferred)</option>
              <option value="20">Group 20 - NIST ECP-384 (CNSA Suite B)</option>
              <option value="31">Group 31 - Curve25519 (Modern Montgomery)</option>
              <option value="14">Group 14 - MODP 2048-bit (Acceptable minimum)</option>
              <option value="2">Group 2 - MODP 1024-bit (Logjam Vulnerable)</option>
              <option value="1">Group 1 - MODP 768-bit (Trivially Broken)</option>
            </select>
          </div>

          {/* PFS Toggle */}
          <div className="flex items-center justify-between p-2.5 bg-slate-900 rounded-lg border border-slate-800">
            <div>
              <div className="text-xs font-semibold text-slate-200">Perfect Forward Secrecy (PFS)</div>
              <div className="text-[10px] text-slate-400">Child SA fresh DH re-exchange</div>
            </div>
            <button
              onClick={() => setPfs(!pfs)}
              className={`px-3 py-1 text-xs font-bold rounded-lg border transition-colors ${
                pfs
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                  : "bg-rose-500/20 text-rose-300 border-rose-500/40"
              }`}
            >
              {pfs ? "ENFORCED" : "DISABLED"}
            </button>
          </div>

          {/* Anti-Replay Toggle */}
          <div className="flex items-center justify-between p-2.5 bg-slate-900 rounded-lg border border-slate-800">
            <div>
              <div className="text-xs font-semibold text-slate-200">Anti-Replay Protection</div>
              <div className="text-[10px] text-slate-400">64-packet sliding window</div>
            </div>
            <button
              onClick={() => setReplay(!replay)}
              className={`px-3 py-1 text-xs font-bold rounded-lg border transition-colors ${
                replay
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                  : "bg-rose-500/20 text-rose-300 border-rose-500/40"
              }`}
            >
              {replay ? "ACTIVE" : "INACTIVE"}
            </button>
          </div>

          {/* SA Lifetime */}
          <div>
            <label className="text-[11px] text-slate-300 font-semibold block mb-1">
              SA Rekey Interval: <span className="font-mono text-cyan-400">{lifetime}s ({Math.round(lifetime / 3600)}h)</span>
            </label>
            <input
              type="range"
              min="600"
              max="36000"
              step="600"
              value={lifetime}
              onChange={(e) => setLifetime(Number(e.target.value))}
              className="w-full accent-cyan-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono">
              <span>10m</span>
              <span>1h (Preferred)</span>
              <span>8h</span>
              <span>10h</span>
            </div>
          </div>
        </div>

        {/* Projected Results Column (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Comparison Score Card */}
          {result && (
            <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider font-bold text-slate-400">
                  Projected Security Posture
                </span>
                {isSimulating && <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />}
              </div>

              <div className="grid grid-cols-3 gap-2 text-center py-2 bg-slate-900/60 rounded-xl border border-slate-800/80">
                {/* Current */}
                <div>
                  <div className="text-[10px] uppercase font-mono text-slate-400">Current Score</div>
                  <div className="text-2xl font-bold font-mono text-slate-300">
                    {result.current_score}
                    <span className="text-xs text-slate-500 font-normal">/100</span>
                  </div>
                  <span className="text-[10px] font-bold text-slate-400">Grade {result.current_grade}</span>
                </div>

                {/* Arrow & Delta */}
                <div className="flex flex-col items-center justify-center">
                  <div className="text-xs font-mono font-bold text-emerald-400 flex items-center">
                    <ArrowUpRight className="w-4 h-4 mr-0.5" />
                    <span>+{result.score_delta} pts</span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono">Improvement</span>
                </div>

                {/* Projected */}
                <div>
                  <div className="text-[10px] uppercase font-mono text-emerald-400">Projected Score</div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {result.projected_score}
                    <span className="text-xs text-emerald-600 font-normal">/100</span>
                  </div>
                  <span className="text-[10px] font-bold text-emerald-400">Grade {result.projected_grade}</span>
                </div>
              </div>

              {/* Resolved vs Remaining Findings */}
              <div className="space-y-2 pt-2">
                <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
                  <span className="flex items-center space-x-1.5 text-emerald-400">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Resolved Findings ({result.resolved_findings.length})</span>
                  </span>
                  <span className="text-slate-500 font-normal">Risks eliminated by proposed hardening</span>
                </div>

                {result.resolved_findings.length > 0 ? (
                  <div className="space-y-1">
                    {result.resolved_findings.map((rf) => (
                      <div
                        key={rf.id}
                        className="text-xs py-1 px-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded flex items-center justify-between text-emerald-300"
                      >
                        <span className="truncate">{rf.title}</span>
                        <span className="font-mono text-[10px] bg-emerald-500/20 px-1.5 py-0.2 rounded">
                          +{Math.abs(rf.score_impact)} pts
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[11px] text-slate-500 italic">No existing findings resolved.</div>
                )}
              </div>

              {/* Generated Configuration Patch */}
              <div className="pt-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Projected Deployment Configuration (strongSwan)</span>
                  </span>
                  <button
                    onClick={copyPatch}
                    className="flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                  >
                    {copiedPatch ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Configuration</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 font-mono text-[11px] text-cyan-300 rounded-lg border border-slate-800 overflow-x-auto max-h-40">
                  {result.config_snippet}
                </pre>
              </div>

              <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-[11px] text-slate-400 flex items-center space-x-2">
                <AlertCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>{result.disclaimer}</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
