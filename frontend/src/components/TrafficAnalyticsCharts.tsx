import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { BarChart3, Activity, PieChart as PieIcon } from "lucide-react";
import { PacketStatistics } from "../types";

interface TrafficAnalyticsChartsProps {
  stats: PacketStatistics;
}

export const TrafficAnalyticsCharts: React.FC<TrafficAnalyticsChartsProps> = ({ stats }) => {
  // Size distribution data
  const sizeData = Object.entries(stats.packet_size_distribution || {}).map(([range, count]) => ({
    range: range.split(" ")[0],
    fullName: range,
    count,
  }));

  // Protocol pie data
  const protoData = [
    { name: "ESP", count: stats.esp_packets, color: "#10b981" },
    { name: "IKE", count: stats.ike_packets, color: "#06b6d4" },
    { name: "AH", count: stats.ah_packets, color: "#f59e0b" },
    { name: "Other", count: stats.other_packets, color: "#64748b" },
  ].filter((p) => p.count > 0);

  // Timeline data
  const timelineData = (stats.timeline_buckets || []).map((b) => ({
    time: `${b.time_sec}s`,
    packets: b.packets,
    bytes: Math.round(b.bytes / 1024),
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* Chart 1: Traffic Volume Timeline */}
      <div className="lg:col-span-2 p-4 bg-slate-900/80 rounded-xl border border-slate-800 shadow-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Packet Rate & Throughput Timeline
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Duration: {stats.duration_seconds}s • {stats.data_rate_kbps} kbps
          </span>
        </div>

        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="packetGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
              />
              <Area
                type="monotone"
                dataKey="packets"
                stroke="#06b6d4"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#packetGrad)"
                name="Packets"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: Packet Size Distribution */}
      <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 shadow-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <BarChart3 className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Packet Size Profile
            </h3>
          </div>
        </div>

        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={sizeData}>
              <XAxis dataKey="range" stroke="#64748b" fontSize={9} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={9} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
              />
              <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} name="Packets" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
