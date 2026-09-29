import React, { useState } from "react";
import { GitBranch, ShieldAlert, ArrowRight, Info, AlertTriangle } from "lucide-react";
import { RiskPathGraph, RiskGraphNode } from "../types";

interface RiskGraphViewProps {
  graph: RiskPathGraph;
}

export const RiskGraphView: React.FC<RiskGraphViewProps> = ({ graph }) => {
  const [selectedNode, setSelectedNode] = useState<RiskGraphNode | null>(
    graph.nodes[1] || graph.nodes[0] || null
  );

  const getNodeColor = (sev: string) => {
    switch (sev) {
      case "Critical":
        return "border-rose-500/80 bg-rose-950/40 text-rose-300 shadow-rose-900/20";
      case "High":
        return "border-orange-500/80 bg-orange-950/40 text-orange-300 shadow-orange-900/20";
      case "Medium":
        return "border-amber-500/80 bg-amber-950/40 text-amber-300 shadow-amber-900/20";
      default:
        return "border-cyan-500/60 bg-cyan-950/40 text-cyan-300 shadow-cyan-900/20";
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400">
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Attack & Risk Path Relationship Graph
            </h2>
            <p className="text-xs text-slate-400">
              Visualizes how isolated cryptographic flaws compound into critical exposure vectors.
            </p>
          </div>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Click any node to inspect cryptanalytic context
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Nodes and Flow Map */}
        <div className="lg:col-span-2 p-5 bg-slate-950/80 rounded-xl border border-slate-800 flex flex-col justify-center min-h-[320px]">
          <div className="flex flex-wrap gap-4 items-center justify-center">
            {graph.nodes.map((node, i) => {
              const isSelected = selectedNode?.id === node.id;
              return (
                <React.Fragment key={node.id}>
                  <div
                    onClick={() => setSelectedNode(node)}
                    className={`p-3 rounded-xl border cursor-pointer transition-all max-w-[210px] text-center shadow-lg select-none ${getNodeColor(
                      node.severity
                    )} ${
                      isSelected
                        ? "ring-2 ring-cyan-400 scale-105"
                        : "hover:scale-102 hover:border-slate-500"
                    }`}
                  >
                    <div className="text-[10px] uppercase font-mono tracking-wider opacity-80 mb-0.5">
                      {node.category}
                    </div>
                    <div className="text-xs font-bold leading-snug">{node.label}</div>
                    <div className="mt-1 text-[9px] font-mono uppercase px-1.5 py-0.5 rounded-full inline-block bg-slate-900/60 border border-current">
                      {node.severity}
                    </div>
                  </div>

                  {i < graph.nodes.length - 1 && (
                    <div className="hidden sm:flex text-slate-600 items-center">
                      <ArrowRight className="w-4 h-4 animate-pulse" />
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>

          {/* Graph Legend */}
          <div className="mt-6 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-center gap-4 text-[11px] text-slate-400">
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span>Critical Compound Vulnerability</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
              <span>High Risk Factor</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500"></span>
              <span>Baseline Node</span>
            </span>
          </div>
        </div>

        {/* Selected Node Details Card */}
        <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 flex flex-col justify-between">
          {selectedNode ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-[11px] font-mono uppercase text-slate-400">Node Details</span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${getNodeColor(selectedNode.severity)}`}>
                  {selectedNode.severity}
                </span>
              </div>

              <div>
                <h3 className="text-sm font-bold text-white mb-1">{selectedNode.label}</h3>
                <div className="text-xs text-cyan-400 font-mono">Category: {selectedNode.category}</div>
              </div>

              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-xs text-slate-300 leading-relaxed">
                {selectedNode.details}
              </div>

              <div className="text-[11px] text-slate-400">
                Connected edges: {graph.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length} links in risk path
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-400">
              Select a node in the graph to view detailed risk analysis
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
