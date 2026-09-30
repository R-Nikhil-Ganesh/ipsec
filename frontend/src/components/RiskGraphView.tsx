/**
 * RiskGraphView — clickable SVG directed graph for attack / risk path visualisation.
 *
 * Layout:   BFS layering (Sugiyama-lite) assigns each node to a depth layer,
 *           then centres siblings within that layer.
 * Edges:    Cubic Bézier curves with per-severity SVG arrowhead markers.
 * Interaction:
 *   • Click any node to select it — unrelated nodes dim, connected edges highlight
 *     and show their relationship label.
 *   • Right-panel shows node details + incoming / outgoing edge lists.
 *   • Zoom with + / − buttons; drag canvas to pan.
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
  Critical:      { fill: "rgba(190,18,60,0.20)",  stroke: "#f43f5e", text: "#fda4af", badge: "rgba(244,63,94,0.28)"  },
  High:          { fill: "rgba(194,65,12,0.20)",  stroke: "#f97316", text: "#fdba74", badge: "rgba(249,115,22,0.28)" },
  Medium:        { fill: "rgba(161,98,7,0.20)",   stroke: "#eab308", text: "#fde047", badge: "rgba(234,179,8,0.28)"  },
  Low:           { fill: "rgba(2,132,199,0.16)",  stroke: "#38bdf8", text: "#7dd3fc", badge: "rgba(56,189,248,0.22)" },
  Informational: { fill: "rgba(6,182,212,0.12)",  stroke: "#22d3ee", text: "#67e8f9", badge: "rgba(34,211,238,0.18)" },
};
const DEF = SEV.Informational;
const sev = (s: string) => SEV[s] ?? DEF;

// ─── Node geometry ────────────────────────────────────────────────────────────
const NW = 172; // node width
const NH = 72;  // node height
const HGAP = 52; // horizontal gap between siblings
const VGAP = 58; // vertical gap between layers

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
  // same-layer: arc above the nodes
  const x1 = src.x + NW, y1 = src.y + NH / 2;
  const x2 = tgt.x,      y2 = tgt.y + NH / 2;
  const arc = NH * 1.1;
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

  // viewBox
  const bbox = useMemo(() => {
    if (!layout.length) return { x: -200, y: -20, w: 400, h: 200 };
    const xs = layout.map(n => n.x), ys = layout.map(n => n.y);
    const pad = 36;
    const x = Math.min(...xs) - pad;
    const y = Math.min(...ys) - pad;
    const w = Math.max(...xs) + NW + pad - x;
    const h = Math.max(...ys) + NH + pad - y;
    return { x, y, w, h };
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

  const zoom = (d: number) => setScale(s => Math.max(0.3, Math.min(2.8, s + d)));
  const reset = () => { setScale(1); setPan({ x: 0, y: 0 }); };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">

      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400">
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Attack &amp; Risk Path Graph
            </h2>
            <p className="text-xs text-slate-400">
              Click any node to trace the attack chain
            </p>
          </div>
        </div>

        {/* Zoom controls */}
        <div className="flex items-center gap-1">
          <button onClick={() => zoom(0.18)} title="Zoom in"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => zoom(-0.18)} title="Zoom out"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button onClick={reset} title="Reset view"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <span className="ml-1 text-[11px] font-mono text-slate-500">
            {Math.round(scale * 100)}%
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* ── SVG Canvas ── */}
        <div
          className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950/80 overflow-hidden relative"
          style={{ minHeight: 400 }}
        >
          <svg
            viewBox={`${bbox.x} ${bbox.y} ${bbox.w} ${bbox.h}`}
            preserveAspectRatio="xMidYMid meet"
            className="w-full"
            style={{
              minHeight: 380,
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
                  markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                  <path d="M0,0 L0,6 L8,3z" fill={st.stroke} fillOpacity="0.9" />
                </marker>
              ))}
              <marker id="arr-dim" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3z" fill="#1e293b" />
              </marker>
              {/* Glow for selected node */}
              <filter id="rgv-glow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="4" result="b" />
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
              const midY = (s.y + NH + t.y) / 2 - 6;

              return (
                <g key={i}>
                  {/* Wide invisible hit zone */}
                  <path d={d} stroke="transparent" strokeWidth={16} fill="none" />
                  <path d={d} fill="none"
                    stroke={hi ? ts.stroke : "#1e293b"}
                    strokeWidth={hi ? 2.4 : 1}
                    strokeOpacity={hi ? 1 : 0.5}
                    strokeDasharray={hi ? undefined : "5 5"}
                    markerEnd={hi ? `url(#arr-${t.severity})` : "url(#arr-dim)"}
                    style={{ transition: "stroke 0.18s, stroke-opacity 0.18s" }}
                  />
                  {/* Edge label — only when highlighted */}
                  {hi && (
                    <text x={midX} y={midY}
                      textAnchor="middle" fontSize="9"
                      fontFamily="ui-monospace,monospace"
                      fill={ts.stroke} fillOpacity="0.9">
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
                    <rect x={-4} y={-4} width={NW + 8} height={NH + 8} rx={14}
                      fill="none" stroke={st.stroke} strokeWidth={1.5}
                      strokeOpacity={0.45} strokeDasharray="7 4" />
                  )}

                  {/* Node body */}
                  <rect width={NW} height={NH} rx={10}
                    fill={st.fill}
                    fillOpacity={dim ? 0.25 : 1}
                    stroke={st.stroke}
                    strokeWidth={isSelected ? 2.4 : 1.4}
                    strokeOpacity={dim ? 0.2 : 1}
                    style={{ transition: "fill-opacity 0.18s, stroke-opacity 0.18s" }}
                  />

                  {/* Category */}
                  <text x={10} y={16} fontSize="8.5"
                    fontFamily="ui-monospace,monospace" fontWeight={700}
                    letterSpacing="0.07em"
                    fill={st.text} fillOpacity={dim ? 0.25 : 0.72}>
                    {node.category.toUpperCase()}
                  </text>

                  {/* Label — rendered as foreignObject for word-wrap */}
                  <foreignObject x={8} y={20} width={NW - 16} height={30}>
                    <div style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: dim ? "#1e293b" : "#f8fafc",
                      lineHeight: 1.3,
                      overflow: "hidden",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}>
                      {node.label}
                    </div>
                  </foreignObject>

                  {/* Severity badge */}
                  <rect x={8} y={NH - 19} width={node.severity.length * 5.8 + 12} height={14}
                    rx={4} fill={st.badge} fillOpacity={dim ? 0.15 : 1} />
                  <text x={14} y={NH - 8} fontSize="8" fontWeight={700}
                    fontFamily="ui-monospace,monospace" letterSpacing="0.05em"
                    fill={st.text} fillOpacity={dim ? 0.2 : 1}>
                    {node.severity.toUpperCase()}
                  </text>

                  {/* Edge-count dot (bottom-right) */}
                  {(() => {
                    const cnt = graph.edges.filter(
                      e => e.source === node.id || e.target === node.id
                    ).length;
                    if (!cnt) return null;
                    return (
                      <g transform={`translate(${NW - 14},10)`}>
                        <circle r={8} fill="rgba(0,0,0,0.45)" stroke={st.stroke} strokeWidth={1} />
                        <text textAnchor="middle" y={4} fontSize="8.5" fontWeight={700}
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
        <div className="flex flex-col gap-3 p-4 bg-slate-950/60 rounded-xl border border-slate-800">
          {sel ? (
            <>
              {/* Header */}
              <div className="flex items-start justify-between pb-2 border-b border-slate-800 gap-2">
                <span className="text-[11px] font-mono uppercase text-slate-400">Node Details</span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold"
                  style={{ color: sev(sel.severity).text, background: sev(sel.severity).badge }}>
                  {sel.severity}
                </span>
              </div>

              {/* Category + label */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider mb-0.5"
                  style={{ color: sev(sel.severity).text, opacity: 0.75 }}>
                  {sel.category}
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">{sel.label}</h3>
              </div>

              {/* Description */}
              <p className="text-xs text-slate-300 leading-relaxed p-3 bg-slate-900 rounded-lg border border-slate-800">
                {sel.details}
              </p>

              {/* Incoming / outgoing */}
              {(() => {
                const inc = graph.edges.filter(e => e.target === sel.id);
                const out = graph.edges.filter(e => e.source === sel.id);
                return (
                  <div className="space-y-2 text-[11px]">
                    {inc.length > 0 && (
                      <div>
                        <div className="font-mono text-slate-500 mb-1">↳ Incoming ({inc.length})</div>
                        {inc.map((e, i) => {
                          const src = nodeMap.get(e.source);
                          return (
                            <button key={i}
                              onClick={() => src && setSel(src)}
                              className="w-full text-left flex items-center gap-1.5 py-0.5 hover:text-white transition-colors">
                              <span className="font-semibold truncate"
                                style={{ color: sev(src?.severity ?? "").text }}>
                                {src?.label ?? e.source}
                              </span>
                              <span className="text-slate-600 font-mono text-[9px] shrink-0">
                                → {e.label}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                    {out.length > 0 && (
                      <div>
                        <div className="font-mono text-slate-500 mb-1">→ Outgoing ({out.length})</div>
                        {out.map((e, i) => {
                          const tgt = nodeMap.get(e.target);
                          return (
                            <button key={i}
                              onClick={() => tgt && setSel(tgt)}
                              className="w-full text-left flex items-center gap-1.5 py-0.5 hover:text-white transition-colors">
                              <span className="text-slate-600 font-mono text-[9px] shrink-0">
                                {e.label} →
                              </span>
                              <span className="font-semibold truncate"
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
          <div className="mt-auto pt-3 border-t border-slate-800 space-y-1.5">
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1.5">Legend</div>
            {(["Critical","High","Medium","Informational"] as const).map(s => (
              <div key={s} className="flex items-center gap-2 text-[11px]">
                <span className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ background: SEV[s]?.stroke }} />
                <span style={{ color: SEV[s]?.text }}>{s}</span>
              </div>
            ))}
            <div className="flex items-center gap-2 text-[11px] text-slate-500 pt-1">
              <span className="inline-block w-5 border-t border-dashed border-slate-600" />
              <span>Dependency edge</span>
            </div>
            <div className="text-[10px] text-slate-600 pt-1">
              Edge badge = connection count
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
