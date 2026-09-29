import React, { useState } from "react";
import { ShieldAlert, AlertTriangle, Info, Check, Copy, ChevronDown, ChevronUp, Terminal } from "lucide-react";
import { SecurityFinding } from "../types";

interface FindingsListProps {
  findings: SecurityFinding[];
}

export const FindingsList: React.FC<FindingsListProps> = ({ findings }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const categories = ["All", ...Array.from(new Set(findings.map((f) => f.category)))];

  const filteredFindings =
    selectedCategory === "All"
      ? findings
      : findings.filter((f) => f.category === selectedCategory);

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "Critical":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "High":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "Medium":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "Low":
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
      default:
        return "bg-slate-700/50 text-slate-300 border-slate-600/50";
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      {/* Header & Filter Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center space-x-2">
            <span>Explainable Security Assessment</span>
            <span className="text-xs px-2 py-0.5 bg-slate-800 text-slate-300 border border-slate-700 rounded-full font-mono">
              {findings.length} Findings
            </span>
          </h2>
          <p className="text-xs text-slate-400">
            Deterministic rule evaluations traceable directly to packet headers and transforms.
          </p>
        </div>

        {/* Category Filters */}
        <div className="flex flex-wrap gap-1.5">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`text-xs px-2.5 py-1 rounded-lg font-medium transition-colors ${
                selectedCategory === cat
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                  : "bg-slate-800/60 hover:bg-slate-800 text-slate-400 border border-slate-700/60"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List Accordion */}
      <div className="space-y-3">
        {filteredFindings.map((f) => {
          const isExpanded = expandedId === f.id;
          return (
            <div
              key={f.id}
              className="border border-slate-800 bg-slate-950/40 rounded-xl overflow-hidden transition-all"
            >
              {/* Card Header */}
              <div
                onClick={() => setExpandedId(isExpanded ? null : f.id)}
                className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/40 select-none transition-colors"
              >
                <div className="flex items-center space-x-3">
                  <div
                    className={`p-1.5 rounded-lg border text-xs font-bold font-mono ${getSeverityBadge(
                      f.severity
                    )}`}
                  >
                    {f.severity.toUpperCase()}
                  </div>

                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-sm font-bold text-slate-100">{f.title}</h3>
                      <span className="text-[11px] font-mono text-slate-400">[{f.id}]</span>
                    </div>
                    <div className="text-xs text-slate-400 flex items-center space-x-3 mt-0.5">
                      <span>Category: <strong>{f.category}</strong></span>
                      <span>•</span>
                      <span>Confidence: <strong>{Math.round(f.confidence * 100)}%</strong></span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  {f.score_impact < 0 ? (
                    <span className="text-xs font-mono font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/30">
                      {f.score_impact} pts
                    </span>
                  ) : (
                    <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      Compliant
                    </span>
                  )}

                  <div className="text-slate-400">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>
              </div>

              {/* Card Body (Expanded) */}
              {isExpanded && (
                <div className="p-4 pt-0 border-t border-slate-800/60 bg-slate-900/40 space-y-3.5 mt-2 text-xs">
                  {/* Why it Matters */}
                  <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800">
                    <span className="text-[11px] uppercase tracking-wider font-bold text-slate-400 block mb-1">
                      Cryptographic Impact & Threat Vector
                    </span>
                    <p className="text-slate-300 leading-relaxed">{f.why_it_matters}</p>
                  </div>

                  {/* Packet Evidence */}
                  <div>
                    <span className="text-[11px] uppercase tracking-wider font-bold text-slate-400 block mb-1">
                      Packet-Level Evidence
                    </span>
                    <div className="p-2.5 bg-slate-950 font-mono text-slate-300 rounded border border-slate-800 text-[11px]">
                      {f.evidence}
                    </div>
                  </div>

                  {/* Recommended Action */}
                  <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg">
                    <span className="text-[11px] uppercase tracking-wider font-bold text-emerald-400 block mb-1">
                      Recommended Remediation
                    </span>
                    <p className="text-emerald-200/90">{f.remediation}</p>
                  </div>

                  {/* Remediation Patch Snippet */}
                  {f.remediation_patch && (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] uppercase tracking-wider font-bold text-slate-400 flex items-center space-x-1">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Verified strongSwan / swanctl.conf Patch</span>
                        </span>
                        <button
                          onClick={() => copyToClipboard(f.remediation_patch || "", f.id)}
                          className="flex items-center space-x-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
                        >
                          {copiedId === f.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy Patch</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="p-3 bg-slate-950 font-mono text-[11px] text-emerald-400 rounded-lg border border-slate-800 overflow-x-auto">
                        {f.remediation_patch}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
