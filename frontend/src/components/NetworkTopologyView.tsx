/**
 * NetworkTopologyView — Rich SVG network topology diagram.
 *
 * Renders a full enterprise network map (two sites + internet cloud) with
 * dummy devices on each side.  When a problematic VPN configuration is
 * detected (weak crypto, legacy DH, replay failures, IKEv1, etc.) the
 * affected nodes flash red, threat-pulse rings appear on the tunnel, and
 * an alert banner explains the risk.
 */
import React, { useMemo, useState } from "react";
import { VPNFingerprint, PacketStatistics, RiskScoreBreakdown } from "../types";

// ─── props ────────────────────────────────────────────────────────────────────
interface NetworkTopologyViewProps {
  fingerprint: VPNFingerprint;
  stats: PacketStatistics;
  riskScore?: RiskScoreBreakdown;
}

// ─── colour palette ───────────────────────────────────────────────────────────
const C = {
  bg: "#0b1120",
  card: "#0f172a",
  border: "#1e293b",
  safe: "#22c55e",
  warn: "#f59e0b",
  crit: "#ef4444",
  info: "#22d3ee",
  dim: "#334155",
  textSafe: "#86efac",
  textWarn: "#fcd34d",
  textCrit: "#fca5a5",
  textInfo: "#67e8f9",
  textDim: "#475569",
};

// ─── threat level ─────────────────────────────────────────────────────────────
type ThreatLevel = "safe" | "warn" | "critical";

function classifyThreat(
  fp: VPNFingerprint,
  riskScore?: RiskScoreBreakdown
): ThreatLevel {
  const score = riskScore?.overall_score;
  if (score !== undefined) {
    if (score < 50) return "critical";
    if (score < 75) return "warn";
    return "safe";
  }
  const dhBad = fp.dh_group && parseInt(fp.dh_group) <= 5;
  const encBad = fp.encryption && /DES|NULL/i.test(fp.encryption);
  if (dhBad || encBad || fp.replay_protection === false) return "critical";
  if (fp.ike_version === "IKEv1" || (fp.dh_group && parseInt(fp.dh_group) < 14))
    return "warn";
  return "safe";
}

function threatColor(level: ThreatLevel) {
  return level === "critical" ? C.crit : level === "warn" ? C.warn : C.safe;
}

// ─── simple SVG icon paths ────────────────────────────────────────────────────
const ICONS: Record<string, string> = {
  server:
    "M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm0 8h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2zm0 8h16a2 2 0 0 1 2 2v2H2v-2a2 2 0 0 1 2-2zM6 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2zm0 8a1 1 0 1 0 0 2 1 1 0 0 0 0-2z",
  firewall:
    "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4l6 2.67V11c0 3.9-2.67 7.54-6 8.93C10.9 17.2 9 14.21 9 11V7.67L12 5z",
  workstation:
    "M20 18c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z",
  switch:
    "M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z",
  cloud:
    "M19.35 10.04A7.49 7.49 0 0 0 12 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 0 0 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z",
  laptop:
    "M20 18c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4z",
  vpn:
    "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4.18L19 8.3V11c0 3.21-1.9 6.2-5 7.93C10.9 17.2 9 14.21 9 11V8.3l3-1.12z",
  iot: "M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z",
  attacker:
    "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15v-4H7l5-8v4h4l-5 8z",
};

function DeviceIcon({
  type,
  cx,
  cy,
  size = 16,
  color = "#94a3b8",
}: {
  type: string;
  cx: number;
  cy: number;
  size?: number;
  color?: string;
}) {
  const path = ICONS[type] ?? ICONS.server;
  return (
    <svg
      x={cx - size / 2}
      y={cy - size / 2}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      overflow="visible"
    >
      <path d={path} fill={color} />
    </svg>
  );
}

// ─── Device definitions ───────────────────────────────────────────────────────
interface DeviceNode {
  id: string;
  label: string;
  sublabel?: string;
  icon: string;
  x: number;
  y: number;
  isGateway?: boolean;
  isFw?: boolean;
  internet?: boolean;
  isAttacker?: boolean;
}

const SITE_A: DeviceNode[] = [
  { id: "ws1",  label: "Workstation A1",   icon: "workstation", x: 52,  y: 90  },
  { id: "ws2",  label: "Workstation A2",   icon: "laptop",      x: 52,  y: 155 },
  { id: "db1",  label: "DB Server",        icon: "server",      x: 52,  y: 225, sublabel: "10.0.1.10" },
  { id: "iot1", label: "IoT Hub",          icon: "iot",         x: 52,  y: 295, sublabel: "10.0.1.50" },
  { id: "sw1",  label: "L3 Switch",        icon: "switch",      x: 165, y: 190, sublabel: "10.0.1.1" },
  { id: "fw1",  label: "Firewall A",       icon: "firewall",    x: 280, y: 190, sublabel: "10.10.0.1",  isFw: true },
  { id: "gw1",  label: "VPN Gateway A",   icon: "vpn",         x: 395, y: 190, sublabel: "203.0.113.1", isGateway: true },
];

const SITE_B: DeviceNode[] = [
  { id: "ws3",  label: "Workstation B1",   icon: "workstation", x: 948, y: 90  },
  { id: "ws4",  label: "Workstation B2",   icon: "laptop",      x: 948, y: 155 },
  { id: "db2",  label: "DB Server",        icon: "server",      x: 948, y: 225, sublabel: "192.168.1.10" },
  { id: "web1", label: "Web Server",       icon: "server",      x: 948, y: 295, sublabel: "192.168.1.20" },
  { id: "sw2",  label: "L3 Switch",        icon: "switch",      x: 835, y: 190, sublabel: "192.168.1.1" },
  { id: "fw2",  label: "Firewall B",       icon: "firewall",    x: 720, y: 190, sublabel: "172.16.0.1",  isFw: true },
  { id: "gw2",  label: "VPN Gateway B",   icon: "vpn",         x: 605, y: 190, sublabel: "198.51.100.1", isGateway: true },
];

const INTERNET_NODES: DeviceNode[] = [
  { id: "cloud",    label: "Internet",       icon: "cloud",    x: 500, y: 190, internet: true },
  { id: "attacker", label: "Threat Actor",   icon: "attacker", x: 500, y: 320, internet: true, isAttacker: true },
];

const EDGES: [string, string][] = [
  ["ws1",  "sw1"],
  ["ws2",  "sw1"],
  ["db1",  "sw1"],
  ["iot1", "sw1"],
  ["sw1",  "fw1"],
  ["fw1",  "gw1"],
  ["gw1",  "cloud"],
  ["cloud","gw2"],
  ["gw2",  "fw2"],
  ["fw2",  "sw2"],
  ["sw2",  "ws3"],
  ["sw2",  "ws4"],
  ["sw2",  "db2"],
  ["sw2",  "web1"],
];

// ─── Component ────────────────────────────────────────────────────────────────
export const NetworkTopologyView: React.FC<NetworkTopologyViewProps> = ({
  fingerprint,
  stats,
  riskScore,
}) => {
  const threat = useMemo(
    () => classifyThreat(fingerprint, riskScore),
    [fingerprint, riskScore]
  );
  const [hoveredGw, setHoveredGw] = useState<string | null>(null);

  const allNodes = useMemo(
    () => [...SITE_A, ...SITE_B, ...INTERNET_NODES],
    []
  );
  const nodeMap = useMemo(() => {
    const m = new Map<string, DeviceNode>();
    allNodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [allNodes]);

  const tc = threatColor(threat);
  const score = riskScore?.overall_score;
  const grade = riskScore?.posture_grade;

  // per-node colour
  function nc(node: DeviceNode): string {
    if (node.internet) return node.isAttacker
      ? (threat === "safe" ? C.dim : tc)
      : "#1e293b";
    if (threat === "safe")  return C.safe;
    if (threat === "warn")  return node.isGateway || node.isFw ? C.warn : "#ca8a04";
    // critical
    return C.crit;
  }

  const alertMessages: Record<ThreatLevel, string> = {
    safe:
      "✓  Tunnel healthy — AES-256-GCM + ECC DH + PFS active. No threat actors detected.",
    warn:
      "⚠  Degraded config — weak DH group or legacy IKEv1 detected. Passive eavesdropping possible.",
    critical:
      "✕  Critical breach risk — broken cipher / compromised key exchange. Adversary can decrypt all sessions.",
  };

  return (
    <div className="space-y-3">
      {/* ── Alert banner ── */}
      <div
        className="flex items-center gap-3 px-4 py-2.5 rounded-lg border text-xs font-medium"
        style={{
          background:
            threat === "safe"
              ? "rgba(22,163,74,0.08)"
              : threat === "critical"
              ? "rgba(220,38,38,0.12)"
              : "rgba(217,119,6,0.10)",
          borderColor:
            threat === "safe"
              ? "rgba(22,163,74,0.35)"
              : threat === "critical"
              ? "rgba(220,38,38,0.50)"
              : "rgba(217,119,6,0.40)",
          color:
            threat === "safe"
              ? C.textSafe
              : threat === "critical"
              ? C.textCrit
              : C.textWarn,
        }}
      >
        <span className="text-base leading-none">
          {threat === "safe" ? "🟢" : threat === "critical" ? "🔴" : "🟡"}
        </span>
        <span className="flex-1">{alertMessages[threat]}</span>
        {score !== undefined && (
          <span className="font-mono font-bold ml-auto whitespace-nowrap">
            {score}/100 &nbsp;{grade}
          </span>
        )}
      </div>

      {/* ── SVG diagram ── */}
      <div
        className="rounded-xl border overflow-x-auto"
        style={{ background: C.bg, borderColor: C.border }}
      >
        <svg
          viewBox="0 0 1000 420"
          style={{ minWidth: 780, display: "block" }}
          role="img"
          aria-label="Enterprise VPN network topology"
        >
          <defs>
            <filter id="ntv-glow-r" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="5" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="ntv-glow-g" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <marker id="ntv-arr-tc" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3z" fill={tc} fillOpacity="0.9" />
            </marker>
            <marker id="ntv-arr-dim" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3z" fill={C.dim} fillOpacity="0.8" />
            </marker>
          </defs>

          {/* ── Zone backgrounds ── */}
          <rect x={8} y={8} width={455} height={402} rx={14}
            fill="rgba(6,182,212,0.03)" stroke="rgba(6,182,212,0.12)" strokeWidth={1} />
          <text x={22} y={28} fontSize={9} fontWeight={700} letterSpacing="0.1em"
            fontFamily="ui-monospace,monospace" fill="rgba(6,182,212,0.45)">
            SITE A — HEADQUARTERS
          </text>

          <rect x={468} y={8} width={64} height={402} rx={14}
            fill="rgba(51,65,85,0.06)" stroke="rgba(51,65,85,0.2)" strokeWidth={1} />
          <text x={477} y={28} fontSize={8} fontWeight={700} letterSpacing="0.08em"
            fontFamily="ui-monospace,monospace" fill="rgba(71,85,105,0.55)">
            WAN
          </text>

          <rect x={537} y={8} width={455} height={402} rx={14}
            fill={
              threat === "safe"
                ? "rgba(34,197,94,0.03)"
                : threat === "critical"
                ? "rgba(239,68,68,0.06)"
                : "rgba(245,158,11,0.04)"
            }
            stroke={
              threat === "safe"
                ? "rgba(34,197,94,0.12)"
                : threat === "critical"
                ? "rgba(239,68,68,0.22)"
                : "rgba(245,158,11,0.18)"
            }
            strokeWidth={1} />
          <text x={551} y={28} fontSize={9} fontWeight={700} letterSpacing="0.1em"
            fontFamily="ui-monospace,monospace"
            fill={
              threat === "safe"
                ? "rgba(34,197,94,0.45)"
                : threat === "critical"
                ? "rgba(239,68,68,0.65)"
                : "rgba(245,158,11,0.55)"
            }>
            SITE B — BRANCH OFFICE
          </text>

          {/* ── Edges (data) ── */}
          {EDGES.map(([sid, tid], i) => {
            const s = nodeMap.get(sid);
            const t = nodeMap.get(tid);
            if (!s || !t) return null;
            const isTunnel = (s.id === "gw1" && t.id === "cloud") ||
                             (s.id === "cloud" && t.id === "gw2");
            const isInternet = s.internet || t.internet;
            const color = isInternet ? C.dim : tc;
            const width = isTunnel ? 3 : (s.isGateway || t.isGateway ? 2 : 1.5);
            return (
              <line
                key={i}
                x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                stroke={color}
                strokeWidth={width}
                strokeOpacity={isInternet ? 0.25 : 0.65}
              />
            );
          })}

          {/* ── Tunnel label ── */}
          <text x={500} y={175} textAnchor="middle" fontSize={9} fontWeight={700}
            fontFamily="ui-monospace,monospace" fill={tc}>
            {fingerprint.ike_version || "IPsec"} · {fingerprint.encryption || "ESP"}
            {" "}· {stats.esp_packets} pkts
          </text>

          {/* ── Threat pulse rings on tunnel midpoint ── */}
          {threat !== "safe" && (
            <>
              <circle cx={500} cy={190} r={20} fill="none"
                stroke={tc} strokeWidth={1.5} strokeOpacity={0.45} strokeDasharray="5 4">
                <animateTransform attributeName="transform" type="rotate"
                  from="0 500 190" to="360 500 190" dur="4s" repeatCount="indefinite" />
              </circle>
              <circle cx={500} cy={190} r={28} fill="none"
                stroke={tc} strokeWidth={0.8} strokeOpacity={0.2}>
                <animate attributeName="r" values="24;36;24" dur="2.8s" repeatCount="indefinite" />
                <animate attributeName="stroke-opacity" values="0.3;0;0.3" dur="2.8s" repeatCount="indefinite" />
              </circle>
            </>
          )}

          {/* ── Attacker node + eavesdrop arrow ── */}
          {(() => {
            const att = nodeMap.get("attacker")!;
            const col = threat === "safe" ? C.dim : tc;
            const glowId = threat === "critical" ? "url(#ntv-glow-r)" : undefined;
            return (
              <g filter={glowId}>
                {/* dashed line to cloud */}
                <line x1={att.x} y1={att.y} x2={500} y2={225}
                  stroke={threat === "safe" ? C.dim : tc}
                  strokeWidth={threat === "safe" ? 1 : 1.8}
                  strokeDasharray="5 4"
                  strokeOpacity={threat === "safe" ? 0.15 : 0.75}
                  markerEnd={threat === "safe" ? "url(#ntv-arr-dim)" : "url(#ntv-arr-tc)"} />

                {/* attacker circle */}
                <circle cx={att.x} cy={att.y} r={22}
                  fill={threat === "safe" ? "rgba(51,65,85,0.3)" : `${col}18`}
                  stroke={col}
                  strokeWidth={threat === "safe" ? 1 : 1.8}
                  strokeOpacity={threat === "safe" ? 0.2 : 1} />

                {threat !== "safe" && (
                  <circle cx={att.x} cy={att.y} r={28} fill="none"
                    stroke={tc} strokeWidth={1} strokeOpacity={0.25}>
                    <animate attributeName="r" values="24;36;24" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite" />
                  </circle>
                )}

                <DeviceIcon type="attacker" cx={att.x} cy={att.y - 4} size={18}
                  color={threat === "safe" ? C.dim : col} />
                <text x={att.x} y={att.y + 34} textAnchor="middle" fontSize={9}
                  fontWeight={700} fontFamily="ui-monospace,monospace" fill={col}
                  fillOpacity={threat === "safe" ? 0.3 : 1}>
                  Threat Actor
                </text>
                {threat !== "safe" && (
                  <text x={att.x + 30} y={att.y + 24} fontSize={8}
                    fontFamily="ui-monospace,monospace" fill={tc}>
                    {threat === "critical" ? "decrypting" : "eavesdrop"}
                  </text>
                )}
              </g>
            );
          })()}

          {/* ── Device nodes ── */}
          {[...SITE_A, ...SITE_B].map((node) => {
            const color = nc(node);
            const r = node.isGateway ? 22 : node.isFw ? 19 : 16;
            const isHov = hoveredGw === node.id;
            const glowFilter =
              threat !== "safe"
                ? "url(#ntv-glow-r)"
                : node.isGateway
                ? "url(#ntv-glow-g)"
                : undefined;

            return (
              <g key={node.id}
                onMouseEnter={() => node.isGateway ? setHoveredGw(node.id) : null}
                onMouseLeave={() => setHoveredGw(null)}
                style={{ cursor: node.isGateway ? "pointer" : "default" }}
                filter={glowFilter}
              >
                {/* Pulse ring for gateways under threat */}
                {node.isGateway && threat !== "safe" && (
                  <circle cx={node.x} cy={node.y} r={r + 4} fill="none"
                    stroke={color} strokeWidth={1.5} strokeOpacity={0.4}>
                    <animate attributeName="r" values={`${r+2};${r+12};${r+2}`}
                      dur="2s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.5;0;0.5"
                      dur="2s" repeatCount="indefinite" />
                  </circle>
                )}

                {/* Node circle */}
                <circle cx={node.x} cy={node.y} r={r}
                  fill={`${color}18`}
                  stroke={color}
                  strokeWidth={node.isGateway ? 2.2 : isHov ? 2 : 1.5} />

                {/* Critical X overlay on non-gateway nodes */}
                {!node.isGateway && !node.isFw && threat === "critical" && (
                  <>
                    <line x1={node.x-7} y1={node.y-7} x2={node.x+7} y2={node.y+7}
                      stroke={C.crit} strokeWidth={1.5} strokeOpacity={0.55} />
                    <line x1={node.x+7} y1={node.y-7} x2={node.x-7} y2={node.y+7}
                      stroke={C.crit} strokeWidth={1.5} strokeOpacity={0.55} />
                  </>
                )}

                <DeviceIcon type={node.icon} cx={node.x} cy={node.y}
                  size={node.isGateway ? 17 : 13} color={color} />

                {/* Label below */}
                <text x={node.x} y={node.y + r + 13} textAnchor="middle"
                  fontSize={node.isGateway ? 9 : 8}
                  fontWeight={node.isGateway ? 700 : 500}
                  fontFamily="ui-monospace,monospace"
                  fill={color}>
                  {node.label}
                </text>
                {node.sublabel && (
                  <text x={node.x} y={node.y + r + 23} textAnchor="middle"
                    fontSize={7} fontFamily="ui-monospace,monospace" fill={C.textDim}
                    fillOpacity={0.7}>
                    {node.sublabel}
                  </text>
                )}

                {/* Hover tooltip for gateway */}
                {isHov && node.isGateway && (
                  <g>
                    <rect
                      x={node.id === "gw1" ? node.x + 26 : node.x - 170}
                      y={node.y - 52}
                      width={164} height={66} rx={8}
                      fill="#0f172a" stroke={color} strokeWidth={1.2} />
                    {[
                      `${fingerprint.ike_version ?? "IKE?"} · ${fingerprint.mode ?? "Tunnel"}`,
                      fingerprint.encryption ?? "cipher unknown",
                      `DH ${fingerprint.dh_group_name ?? fingerprint.dh_group ?? "?"}`,
                      `PFS: ${fingerprint.pfs === true ? "✓" : fingerprint.pfs === false ? "✕" : "?"}  Replay: ${fingerprint.replay_protection === true ? "✓" : "✕"}`,
                    ].map((line, i) => (
                      <text key={i}
                        x={(node.id === "gw1" ? node.x + 26 : node.x - 170) + 10}
                        y={node.y - 52 + 16 + i * 13}
                        fontSize={i === 0 ? 9 : 8}
                        fontWeight={i === 0 ? 700 : 400}
                        fontFamily="ui-monospace,monospace"
                        fill={i === 0 ? color : "#94a3b8"}>
                        {line}
                      </text>
                    ))}
                  </g>
                )}
              </g>
            );
          })}

          {/* ── Cloud node ── */}
          {(() => {
            const cloud = nodeMap.get("cloud")!;
            return (
              <g>
                <circle cx={cloud.x} cy={cloud.y} r={20}
                  fill="rgba(30,41,59,0.5)" stroke={C.dim} strokeWidth={1} strokeOpacity={0.4} />
                <DeviceIcon type="cloud" cx={cloud.x} cy={cloud.y} size={18} color={C.textDim} />
                <text x={cloud.x} y={cloud.y + 33} textAnchor="middle" fontSize={8}
                  fontFamily="ui-monospace,monospace" fill={C.textDim} fillOpacity={0.6}>
                  Internet
                </text>
              </g>
            );
          })()}

          {/* ── Legend ── */}
          {[
            { color: C.safe, label: "Healthy" },
            { color: C.warn, label: "Degraded" },
            { color: C.crit, label: "Critical" },
          ].map((l, i) => (
            <g key={l.label} transform={`translate(${20 + i * 105}, 398)`}>
              <circle cx={6} cy={0} r={5} fill={l.color} fillOpacity={0.8} />
              <text x={15} y={4} fontSize={8.5} fontFamily="ui-monospace,monospace" fill="#64748b">
                {l.label}
              </text>
            </g>
          ))}
          <g transform="translate(340, 398)">
            <line x1={0} y1={0} x2={18} y2={0} stroke={C.dim} strokeWidth={1.5} strokeDasharray="4 3" />
            <text x={23} y={4} fontSize={8.5} fontFamily="ui-monospace,monospace" fill="#64748b">Attacker path</text>
          </g>
        </svg>
      </div>

      {/* ── Status chips ── */}
      <div className="flex flex-wrap gap-2">
        {[
          { k: "IKE",        v: fingerprint.ike_version ?? "unknown",  bad: fingerprint.ike_version === "IKEv1" },
          { k: "Cipher",     v: fingerprint.encryption ?? "unknown",   bad: !!fingerprint.encryption && /DES|NULL/i.test(fingerprint.encryption) },
          { k: "DH Group",   v: fingerprint.dh_group_name?.split(" ")[0] ?? `Group ${fingerprint.dh_group ?? "?"}`, bad: !!fingerprint.dh_group && parseInt(fingerprint.dh_group) < 14 },
          { k: "PFS",        v: fingerprint.pfs === true ? "On" : fingerprint.pfs === false ? "Off" : "unknown",    bad: fingerprint.pfs === false },
          { k: "Anti-Replay",v: fingerprint.replay_protection === true ? "Active" : fingerprint.replay_protection === false ? "Violated" : "unknown", bad: fingerprint.replay_protection === false },
          { k: "ESP pkts",   v: String(stats.esp_packets),             bad: false },
        ].map((c) => (
          <span key={c.k} className="text-[11px] px-2.5 py-1 rounded-full border font-mono"
            style={c.bad
              ? { background: "rgba(239,68,68,0.10)", borderColor: "rgba(239,68,68,0.38)", color: "#fca5a5" }
              : { background: "rgba(6,182,212,0.07)", borderColor: "rgba(6,182,212,0.25)", color: "#67e8f9" }
            }>
            <span className="opacity-60">{c.k}: </span>
            <strong>{c.v}</strong>
          </span>
        ))}
      </div>
    </div>
  );
};
