import React from "react";
import { Cpu, Server, Network, ShieldCheck, Eye, HelpCircle } from "lucide-react";
import { VPNFingerprint, PacketStatistics } from "../types";

interface DigitalTwinViewProps {
  fingerprint: VPNFingerprint;
  stats: PacketStatistics;
}

export const DigitalTwinView: React.FC<DigitalTwinViewProps> = ({
  fingerprint,
  stats,
}) => {
  const p = fingerprint.peer_info;

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case "OBSERVED":
        return (
          <span className="text-[10px] px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded font-mono font-bold flex items-center space-x-1">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
      case "INFERRED":
        return (
          <span className="text-[10px] px-2 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded font-mono font-bold flex items-center space-x-1">
            <Cpu className="w-3 h-3" />
            <span>INFERRED</span>
          </span>
        );
      default:
        return (
          <span className="text-[10px] px-2 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 rounded font-mono font-bold flex items-center space-x-1">
            <HelpCircle className="w-3 h-3" />
            <span>UNKNOWN</span>
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <span>VPN Security Digital Twin</span>
              <span className="text-xs px-2 py-0.5 bg-cyan-950 text-cyan-300 border border-cyan-800 rounded-full font-mono">
                {fingerprint.protocol} {fingerprint.mode || "Tunnel"}
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Normalized state reconstructed from packet headers and cryptographic exchanges.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-1 text-slate-400">
            <span className="font-semibold text-slate-300">Confidence:</span>
            <span className="font-mono text-cyan-400 font-bold">
              {Math.round(fingerprint.confidence * 100)}%
            </span>
          </div>
          <span className="text-slate-600">•</span>
          <div className="flex items-center space-x-1 text-slate-400">
            <span className="font-semibold text-slate-300">Total Packets:</span>
            <span className="font-mono text-slate-200">{stats.total_packets}</span>
          </div>
        </div>
      </div>

      {/* Network Topology Gateway Endpoints */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
        {/* Peer Initiator */}
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-semibold flex items-center space-x-1">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              <span>Initiator Gateway (Peer A)</span>
            </span>
            <span className="font-mono text-[10px] text-slate-500">{p?.ip_version || "IPv4"}</span>
          </div>
          <div className="font-mono font-bold text-sm text-white">
            {p?.initiator_ip || "192.168.1.100"}
            <span className="text-slate-500 text-xs font-normal">:{p?.initiator_port || 500}</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono truncate">
            SPI: {fingerprint.evidence?.ike_evidence?.transforms_dh?.[0]?.spi || p?.spi_initiator || "0x0000000000000000"}
          </div>
        </div>

        {/* Encrypted Tunnel Path */}
        <div className="text-center px-2 py-1 flex flex-col items-center">
          <div className="text-[11px] font-mono text-cyan-400 uppercase tracking-widest font-semibold flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            <span>{fingerprint.mode || "Tunnel"} Mode ({fingerprint.encryption || "Encrypted"})</span>
          </div>
          <div className="w-full my-2 flex items-center">
            <div className="h-0.5 bg-gradient-to-r from-cyan-500/20 via-cyan-400 to-cyan-500/20 flex-1"></div>
            <div className="p-1 bg-slate-800 rounded-full border border-cyan-500/50 text-cyan-400 mx-2">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div className="h-0.5 bg-gradient-to-r from-cyan-500/20 via-cyan-400 to-cyan-500/20 flex-1"></div>
          </div>
          <div className="text-[10px] text-slate-400 flex items-center space-x-2">
            <span>NAT-T: <strong>{fingerprint.nat_traversal ? "UDP 4500 Encap" : "Direct IP 50"}</strong></span>
            <span>•</span>
            <span>Replay: <strong>{fingerprint.replay_protection ? "64-pkt Window" : "None"}</strong></span>
          </div>
        </div>

        {/* Peer Responder */}
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-semibold flex items-center space-x-1">
              <Server className="w-3.5 h-3.5 text-emerald-400" />
              <span>Responder Gateway (Peer B)</span>
            </span>
            <span className="font-mono text-[10px] text-slate-500">{p?.ip_version || "IPv4"}</span>
          </div>
          <div className="font-mono font-bold text-sm text-white">
            {p?.responder_ip || "203.0.113.1"}
            <span className="text-slate-500 text-xs font-normal">:{p?.responder_port || 500}</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono truncate">
            SPI: {p?.spi_responder || "0x0000000000000000"}
          </div>
        </div>
      </div>

      {/* Normalized Security Parameters Matrix Table */}
      <div>
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
          Observed Security Attributes vs Heuristics
        </h3>

        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Parameter</th>
                <th className="py-2.5 px-3">Observed Value</th>
                <th className="py-2.5 px-3">Evidence State</th>
                <th className="py-2.5 px-3">Trace Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">IKE Version</td>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">{fingerprint.ike_version || "Not In Trace"}</td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.ike_version_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  {fingerprint.ike_version ? `Decoded from UDP 500/4500 ISAKMP header flags` : "Phase 1 handshake absent from capture"}
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">Encryption Suite</td>
                <td className="py-2.5 px-3 text-white font-bold">{fingerprint.encryption || "Unknown"}</td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.encryption_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  Extracted from IKE proposal transforms (ENCR transform ID)
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">Diffie-Hellman Group</td>
                <td className="py-2.5 px-3 text-white font-bold">
                  {fingerprint.dh_group_name || `Group ${fingerprint.dh_group || "Unknown"}`}
                </td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.dh_group_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  Key Exchange (KE) payload public key length ({fingerprint.dh_group ? `${fingerprint.dh_group}` : "N/A"})
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">Perfect Forward Secrecy (PFS)</td>
                <td className="py-2.5 px-3 text-white font-bold">
                  {fingerprint.pfs === true ? "Enabled" : fingerprint.pfs === false ? "Disabled" : "Unknown"}
                </td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.pfs_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  Phase 2 / Child SA ephemeral DH transform re-negotiation check
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">Anti-Replay Protection</td>
                <td className="py-2.5 px-3 text-white font-bold">
                  {fingerprint.replay_protection ? "Active (Monotonic)" : "Inactive / Duplicate detected"}
                </td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.replay_protection_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  Sequence number progression across {stats.esp_packets} ESP packets
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 text-slate-300 font-sans font-medium">SA Lifetime</td>
                <td className="py-2.5 px-3 text-white font-bold">
                  {fingerprint.sa_lifetime ? `${fingerprint.sa_lifetime}s` : "Unknown"}
                </td>
                <td className="py-2.5 px-3">{renderStatusBadge(fingerprint.sa_lifetime_status)}</td>
                <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px]">
                  IKE duration transform attribute or rekey interval
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
