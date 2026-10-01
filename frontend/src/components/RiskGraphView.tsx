/**
 * RiskGraphView — compact, clickable SVG directed graph for attack / risk path visualisation.
 *
 * Features:
 *   • Proportional virtual canvas sizing (never stretches into giant billboards)
 *   • Sleek, compact node geometry (142px × 56px)
 *   • BFS layering (Sugiyama-lite) with auto-centering
 *   • Click any node to highlight attack paths, dim unrelated nodes
 *   • Smooth zoom and pan
 */
import React, {
  useMemo,
  useState,
  useRef,
  useCallback,
  useEffect,
} from "react";
import { GitBranch, ZoomIn, ZoomOut, RefreshCw } from "lucide-react";
import { RiskPathGraph, RiskGraphNode } from "../types";

// ─── Types ────────────────────────────────────────────────────────────────────
interface Props {
  graph: RiskPathGraph;
}

interface LayoutNode extends RiskGraphNode {
  x: number;
  y: number;
  layer: number;
}

// ─── Severity colour tokens ───────────────────────────────────────────────────
const SEV: Record<string, { fill: string; stroke: string; text: string; badge: string }> = {
  Critical:      { fill: "rgba(190,18,60,0.18)",  stroke: "#f43f5e", text: "#fda4af", badge: "rgba(244,63,94,0.26)"  },
  High:          { fill: "rgba(194,65,12,0.18)",  stroke: "#f97316", text: "#fdba74", badge: "rgba(249,115,22,0.26)" },
  Medium:        { fill: "rgba(161,98,7,0.18)",   stroke: "#eab308", text: "#fde047", badge: "rgba(234,179,8,0.26)"  },
  Low:           { fill: "rgba(2,132,199,0.14)",  stroke: "#38bdf8", text: "#7dd3fc", badge: "rgba(56,189,248,0.20)" },
  Informational: { fill: "rgba(6,182,212,0.10)",  stroke: "#22d3ee", text: "#67e8f9", badge: "rgba(34,211,238,0.16)" },
};
const DEF = SEV.Informational;
const sev = (s: string) => SEV[s] ?? DEF;

// ─── Node geometry (compact & crisp) ──────────────────────────────────────────
const NW = 142; // node width
const NH = 56;  // node height
const HGAP = 32; // horizontal gap between siblings
const VGAP = 42; // vertical gap between layers

// ─── Layout engine ────────────────────────────────────────────────────────────
function computeLayout(nodes: RiskGraphNode[], edges: { source: string; target: string }[]): LayoutNode[] {
  if (!nodes.length) return [];

  const adjOut = new Map<string, string[]>();
  const adjIn  = new Map<string, string[]>();
  for (const n of nodes) { adjOut.set(n.id, []); adjIn.set(n.id, []); }
  for (const e of edges) {
    adjOut.get(e.source)?.push(e.target);
    adjIn.get(e.target)?.push(e.source);
  }

  // BFS layering from roots (in-degree 0)
  const layer = new Map<string, number>();
  const roots = nodes.filter(n => (adjIn.get(n.id)?.length ?? 0) === 0).map(n => n.id);
  const queue = roots.length ? [...roots] : [nodes[0].id];
  queue.forEach(id => layer.set(id, 0));
  let head = 0;
  while (head < queue.length) {
    const cur = queue[head++];
    const cl = layer.get(cur) ?? 0;
    for (const nxt of adjOut.get(cur) ?? []) {
      if (!layer.has(nxt) || layer.get(nxt)! < cl + 1) {
        layer.set(nxt, cl + 1);
        queue.push(nxt);
      }
    }
  }
  nodes.forEach(n => { if (!layer.has(n.id)) layer.set(n.id, 0); });

  // Group by layer
  const byLayer = new Map<number, string[]>();
  for (const [id, l] of layer) {
    if (!byLayer.has(l)) byLayer.set(l, []);
    byLayer.get(l)!.push(id);
  }

  // Assign (x, y) — centre each layer's nodes horizontally
  const pos = new Map<string, { x: number; y: number }>();
  for (const [l, ids] of byLayer) {
    const totalW = ids.length * NW + (ids.length - 1) * HGAP;
    ids.forEach((id, i) => {
      pos.set(id, {
        x: -totalW / 2 + i * (NW + HGAP),
        y: l * (NH + VGAP),
      });
    });
  }

  return nodes.map(n => ({
    ...n,
    x: pos.get(n.id)?.x ?? 0,
    y: pos.get(n.id)?.y ?? 0,
    layer: layer.get(n.id) ?? 0,
  }));
}

// ─── Edge path helpers ────────────────────────────────────────────────────────
function bezierDown(src: LayoutNode, tgt: LayoutNode): string {
  const x1 = src.x + NW / 2, y1 = src.y + NH;
  const x2 = tgt.x + NW / 2, y2 = tgt.y;
  const cy = Math.abs(y2 - y1) * 0.5;
  return `M${x1},${y1} C${x1},${y1 + cy} ${x2},${y2 - cy} ${x2},${y2}`;
}

function bezierSide(src: LayoutNode, tgt: LayoutNode): string {
  const x1 = src.x + NW, y1 = src.y + NH / 2;
  const x2 = tgt.x,      y2 = tgt.y + NH / 2;
  const arc = NH * 0.9;
  return `M${x1},${y1} C${x1 + arc},${y1 - arc} ${x2 - arc},${y2 - arc} ${x2},${y2}`;
}

// ─── Component ────────────────────────────────────────────────────────────────
export const RiskGraphView: React.FC<Props> = ({ graph }) => {
  const [sel, setSel] = useState<RiskGraphNode | null>(
    graph.nodes[1] ?? graph.nodes[0] ?? null
  );
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const dragging = useRef(false);
  const dragOrigin = useRef({ mx: 0, my: 0, px: 0, py: 0 });

  // Reset view when graph changes
  useEffect(() => {
    setSel(graph.nodes[1] ?? graph.nodes[0] ?? null);
    setScale(1);
    setPan({ x: 0, y: 0 });
  }, [graph]);

  // Layout
  const layout = useMemo(() => computeLayout(graph.nodes, graph.edges), [graph]);
  const nodeMap = useMemo(() => {
    const m = new Map<string, LayoutNode>();
    layout.forEach(n => m.set(n.id, n));
    return m;
  }, [layout]);

  // Proportional viewBox: enforces a minimum width/height so small graphs don't over-stretch
  const bbox = useMemo(() => {
    if (!layout.length) return { x: -300, y: -20, w: 600, h: 300 };
    const xs = layout.map(n => n.x), ys = layout.map(n => n.y);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs) + NW;
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys) + NH;

    const rawW = maxX - minX;
    const rawH = maxY - minY;

    // Minimum canvas of 600×290 ensures nodes stay sleek and compact
    const targetW = Math.max(rawW + 120, 600);
    const targetH = Math.max(rawH + 80, 290);

    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;

    return {
      x: midX - targetW / 2,
      y: midY - targetH / 2,
      w: targetW,
      h: targetH,
    };
  }, [layout]);

  // Which edge indices touch the selected node
  const selEdges = useMemo(() => {
    if (!sel) return new Set<number>();
    return new Set(
      graph.edges.flatMap((e, i) =>
        e.source === sel.id || e.target === sel.id ? [i] : []
      )
    );
  }, [sel, graph.edges]);

  // Drag / pan
  const onMouseDown = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if ((e.target as Element).closest("[data-node]")) return;
    dragging.current = true;
    dragOrigin.current = { mx: e.clientX, my: e.clientY, px: pan.x, py: pan.y };
  }, [pan]);
  const onMouseMove = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (!dragging.current) return;
    const { mx, my, px, py } = dragOrigin.current;
    setPan({ x: px + e.clientX - mx, y: py + e.clientY - my });
  }, []);
  const onMouseUp = useCallback(() => { dragging.current = false; }, []);

  const zoom = (d: number) => setScale(s => Math.max(0.4, Math.min(2.5, s + d)));
  const reset = () => { setScale(1); setPan({ x: 0, y: 0 }); };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-xl space-y-3">

      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2.5 border-b border-slate-800 gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400">
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              Attack &amp; Risk Path Graph
            </h2>
            <p className="text-[11px] text-slate-400">
              Interactive vulnerability chaining — click any node to isolate the risk flow
            </p>
          </div>
        </div>

        {/* Zoom controls */}
        <div className="flex items-center gap-1">
          <button onClick={() => zoom(0.15)} title="Zoom in"
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => zoom(-0.15)} title="Zoom out"
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button onClick={reset} title="Reset view"
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <span className="ml-1 text-[10px] font-mono text-slate-500">
            {Math.round(scale * 100)}%
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3.5">

        {/* ── SVG Canvas ── */}
        <div
          className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950/80 overflow-hidden relative h-[330px]"
        >
          <svg
            viewBox={`${bbox.x} ${bbox.y} ${bbox.w} ${bbox.h}`}
            preserveAspectRatio="xMidYMid meet"
            className="w-full h-full"
            style={{
              cursor: "grab",
              transform: `translate(${pan.x}px,${pan.y}px) scale(${scale})`,
              transformOrigin: "center center",
              transition: dragging.current ? "none" : "transform 0.12s ease",
              display: "block",
            }}
            onMouseDown={onMouseDown}
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseUp}
          >
            <defs>
              {/* Arrowhead per severity */}
              {Object.entries(SEV).map(([s, st]) => (
                <marker key={s} id={`arr-${s}`}
                  markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L6,3z" fill={st.stroke} fillOpacity="0.9" />
                </marker>
              ))}
              <marker id="arr-dim" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3z" fill="#1e293b" />
              </marker>
              {/* Subtle glow for selected node */}
              <filter id="rgv-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="b" />
                <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            {/* ── Edges ── */}
            {graph.edges.map((edge, i) => {
              const s = nodeMap.get(edge.source);
              const t = nodeMap.get(edge.target);
              if (!s || !t) return null;

              const hi = selEdges.has(i);
              const ts = sev(t.severity);
              const d = s.layer === t.layer ? bezierSide(s, t) : bezierDown(s, t);
              const midX = (s.x + NW / 2 + t.x + NW / 2) / 2;
              const midY = (s.y + NH + t.y) / 2 - 5;

              return (
                <g key={i}>
                  {/* Invisible hit zone */}
                  <path d={d} stroke="transparent" strokeWidth={14} fill="none" />
                  <path d={d} fill="none"
                    stroke={hi ? ts.stroke : "#1e293b"}
                    strokeWidth={hi ? 1.8 : 1}
                    strokeOpacity={hi ? 1 : 0.45}
                    strokeDasharray={hi ? undefined : "4 4"}
                    markerEnd={hi ? `url(#arr-${t.severity})` : "url(#arr-dim)"}
                    style={{ transition: "stroke 0.15s, stroke-opacity 0.15s" }}
                  />
                  {/* Edge label — only when highlighted */}
                  {hi && (
                    <text x={midX} y={midY}
                      textAnchor="middle" fontSize="8"
                      fontFamily="ui-monospace,monospace"
                      fontWeight={600}
                      fill={ts.stroke} fillOpacity="0.95">
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* ── Nodes ── */}
            {layout.map(node => {
              const st = sev(node.severity);
              const isSelected = sel?.id === node.id;
              const isNeighbour = !isSelected && graph.edges.some(
                e => (e.source === node.id && e.target === sel?.id) ||
                     (e.target === node.id && e.source === sel?.id)
              );
              const dim = !!sel && !isSelected && !isNeighbour;

              return (
                <g key={node.id}
                  data-node="true"
                  transform={`translate(${node.x},${node.y})`}
                  onClick={() => setSel(isSelected ? null : node)}
                  onKeyDown={e => e.key === "Enter" && setSel(isSelected ? null : node)}
                  role="button"
                  tabIndex={0}
                  aria-label={`${node.label} (${node.severity})`}
                  style={{ cursor: "pointer", outline: "none" }}
                  filter={isSelected ? "url(#rgv-glow)" : undefined}
                >
                  {/* Selection ring */}
                  {isSelected && (
                    <rect x={-3} y={-3} width={NW + 6} height={NH + 6} rx={11}
                      fill="none" stroke={st.stroke} strokeWidth={1.4}
                      strokeOpacity={0.45} strokeDasharray="6 3" />
                  )}

                  {/* Node body */}
                  <rect width={NW} height={NH} rx={8}
                    fill={st.fill}
                    fillOpacity={dim ? 0.20 : 1}
                    stroke={st.stroke}
                    strokeWidth={isSelected ? 2 : 1.2}
                    strokeOpacity={dim ? 0.2 : 1}
                    style={{ transition: "fill-opacity 0.15s, stroke-opacity 0.15s" }}
                  />

                  {/* Category */}
                  <text x={8} y={13} fontSize="7.5"
                    fontFamily="ui-monospace,monospace" fontWeight={700}
                    letterSpacing="0.06em"
                    fill={st.text} fillOpacity={dim ? 0.25 : 0.75}>
                    {node.category.toUpperCase()}
                  </text>

                  {/* Label — rendered as foreignObject for word-wrap */}
                  <foreignObject x={8} y={16} width={NW - 16} height={24}>
                    <div style={{
                      fontSize: 9.5,
                      fontWeight: 700,
                      color: dim ? "#1e293b" : "#f8fafc",
                      lineHeight: 1.22,
                      overflow: "hidden",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}>
                      {node.label}
                    </div>
                  </foreignObject>

                  {/* Severity badge */}
                  <rect x={8} y={NH - 15} width={node.severity.length * 5.2 + 8} height={11}
                    rx={3} fill={st.badge} fillOpacity={dim ? 0.15 : 1} />
                  <text x={12} y={NH - 6.5} fontSize="7" fontWeight={700}
                    fontFamily="ui-monospace,monospace" letterSpacing="0.04em"
                    fill={st.text} fillOpacity={dim ? 0.2 : 1}>
                    {node.severity.toUpperCase()}
                  </text>

                  {/* Edge-count dot (top-right) */}
                  {(() => {
                    const cnt = graph.edges.filter(
                      e => e.source === node.id || e.target === node.id
                    ).length;
                    if (!cnt) return null;
                    return (
                      <g transform={`translate(${NW - 11}, 9)`}>
                        <circle r={6.5} fill="rgba(0,0,0,0.5)" stroke={st.stroke} strokeWidth={0.9} />
                        <text textAnchor="middle" y={3} fontSize="7.5" fontWeight={700}
                          fontFamily="ui-monospace,monospace" fill={st.text}>
                          {cnt}
                        </text>
                      </g>
                    );
                  })()}
                </g>
              );
            })}
          </svg>

          {/* Stats overlay */}
          <div className="absolute bottom-2 left-3 text-[10px] font-mono text-slate-600 pointer-events-none">
            {graph.nodes.length} nodes · {graph.edges.length} edges
          </div>
        </div>

        {/* ── Detail panel ── */}
        <div className="flex flex-col gap-2.5 p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 h-[330px] overflow-y-auto">
          {sel ? (
            <>
              {/* Header */}
              <div className="flex items-start justify-between pb-1.5 border-b border-slate-800 gap-2">
                <span className="text-[10px] font-mono uppercase text-slate-400">Node Details</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold"
                  style={{ color: sev(sel.severity).text, background: sev(sel.severity).badge }}>
                  {sel.severity}
                </span>
              </div>

              {/* Category + label */}
              <div>
                <div className="text-[9px] font-mono uppercase tracking-wider mb-0.5"
                  style={{ color: sev(sel.severity).text, opacity: 0.75 }}>
                  {sel.category}
                </div>
                <h3 className="text-xs font-bold text-white leading-snug">{sel.label}</h3>
              </div>

              {/* Description */}
              <p className="text-[11px] text-slate-300 leading-relaxed p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                {sel.details}
              </p>

              {/* Incoming / outgoing */}
              {(() => {
                const inc = graph.edges.filter(e => e.target === sel.id);
                const out = graph.edges.filter(e => e.source === sel.id);
                return (
                  <div className="space-y-1.5 text-[10px]">
                    {inc.length > 0 && (
                      <div>
                        <div className="font-mono text-slate-500 mb-0.5">↳ Incoming ({inc.length})</div>
                        {inc.map((e, i) => {
                          const src = nodeMap.get(e.source);
                          return (
                            <button key={i}
                              onClick={() => src && setSel(src)}
                              className="w-full text-left flex items-center gap-1.5 py-0.5 hover:text-white transition-colors">
                              <span className="font-semibold truncate max-w-[130px]"
                                style={{ color: sev(src?.severity ?? "").text }}>
                                {src?.label ?? e.source}
                              </span>
                              <span className="text-slate-600 font-mono text-[8.5px] shrink-0">
                                → {e.label}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                    {out.length > 0 && (
                      <div>
                        <div className="font-mono text-slate-500 mb-0.5">→ Outgoing ({out.length})</div>
                        {out.map((e, i) => {
                          const tgt = nodeMap.get(e.target);
                          return (
                            <button key={i}
                              onClick={() => tgt && setSel(tgt)}
                              className="w-full text-left flex items-center gap-1.5 py-0.5 hover:text-white transition-colors">
                              <span className="text-slate-600 font-mono text-[8.5px] shrink-0">
                                {e.label} →
                              </span>
                              <span className="font-semibold truncate max-w-[130px]"
                                style={{ color: sev(tgt?.severity ?? "").text }}>
                                {tgt?.label ?? e.target}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                    {inc.length === 0 && out.length === 0 && (
                      <span className="text-slate-600">No connections</span>
                    )}
                  </div>
                );
              })()}
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-xs text-slate-500 text-center">
              Click any node in the graph<br />to inspect it
            </div>
          )}

          {/* Legend */}
          <div className="mt-auto pt-2 border-t border-slate-800 space-y-1">
            <div className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">Legend</div>
            <div className="grid grid-cols-2 gap-x-2 gap-y-1">
              {(["Critical","High","Medium","Informational"] as const).map(s => (
                <div key={s} className="flex items-center gap-1.5 text-[10px]">
                  <span className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: SEV[s]?.stroke }} />
                  <span style={{ color: SEV[s]?.text }}>{s}</span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-500 pt-0.5">
              <span className="inline-block w-4 border-t border-dashed border-slate-600" />
              <span>Attack chain dependency</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};