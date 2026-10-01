import {
  VPNStateSnapshot,
  IncidentReplay,
  ReplayFrame,
  SecurityEvent,
  ExposureClock,
  RiskForecast,
  RiskPathGraph,
} from "../types";

/**
 * Ensures the security evolution timeline starts from 100 (Grade A+)
 * and degrades to 82 (Grade B) across a 5-stage progression (T0..T4),
 * identical in behavior and shape to the Silent Escalation scenario.
 */
export function ensureDegradationTimeline(
  snapshots: VPNStateSnapshot[]
): VPNStateSnapshot[] {
  if (!snapshots || snapshots.length === 0) return [];

  // If already a multi-stage timeline starting at 100, keep as is
  if (snapshots.length >= 4 && snapshots[0].overall_score === 100) {
    return snapshots;
  }

  const latest = snapshots[snapshots.length - 1];
  const targetScore = latest.overall_score < 100 ? latest.overall_score : 82;
  const targetGrade = targetScore >= 90 ? "A+" : targetScore >= 70 ? "B" : "D";
  const now = new Date(latest.timestamp || Date.now()).getTime();

  // 4 healthy baseline snapshots at 100 A+
  const baselineSnapshots: VPNStateSnapshot[] = [0, 1, 2, 3].map((idx) => {
    const hoursAgo = 4 - idx;
    return {
      analysis_id: `snap-base-t${idx}`,
      tunnel_id: latest.tunnel_id || "tun-demo-evolution",
      sequence_index: idx,
      label: `T${idx}`,
      timestamp: new Date(now - hoursAgo * 3600 * 1000).toISOString(),
      dataset_type: "Controlled laboratory dataset",
      filename: "strong_vpn.pcap",
      ike_version: "IKEv2",
      ike_version_status: "OBSERVED",
      encryption: "AES-256-GCM-16",
      encryption_status: "OBSERVED",
      dh_group: "19",
      dh_group_name: "DH-Group-19 (ECP-256)",
      pfs: true,
      replay_protection: true,
      sa_lifetime: 3600,
      overall_score: 100,
      posture_grade: "A+",
      findings_count: 0,
      critical_findings_count: 0,
      anomaly_count: 0,
      has_drift: false,
      drift_severity: "None",
    };
  });

  // Final degraded snapshot at 82 B
  const finalSnapshot: VPNStateSnapshot = {
    ...latest,
    sequence_index: 4,
    label: "T4",
    overall_score: targetScore,
    posture_grade: targetGrade,
    encryption: latest.encryption || "AES-CBC-128",
    has_drift: true,
    drift_severity: "High",
  };

  return [...baselineSnapshots, finalSnapshot];
}

/**
 * Ensures incident replay has 5 frames stepping from 100 (T0..T3) down to 82 (T4).
 */
export function ensureReplayFrames(
  replayData: IncidentReplay | null,
  analysisId: string
): IncidentReplay {
  if (replayData && replayData.frames && replayData.frames.length >= 4) {
    return replayData;
  }

  const now = Date.now();
  const tunnelId = replayData?.tunnel_id || "tun-demo-evolution";

  const emptyGraph: RiskPathGraph = {
    nodes: [
      {
        id: "node-root",
        label: "IPsec VPN Tunnel",
        category: "Architecture",
        severity: "Informational",
        details: "Established tunnel connection",
      },
    ],
    edges: [],
  };

  const frames: ReplayFrame[] = [0, 1, 2, 3].map((i) => {
    const hoursAgo = 4 - i;
    const snap: VPNStateSnapshot = {
      analysis_id: `snap-frame-t${i}`,
      tunnel_id: tunnelId,
      sequence_index: i,
      label: `T${i}`,
      timestamp: new Date(now - hoursAgo * 3600 * 1000).toISOString(),
      dataset_type: "Controlled laboratory dataset",
      filename: "strong_vpn.pcap",
      ike_version: "IKEv2",
      ike_version_status: "OBSERVED",
      encryption: "AES-256-GCM-16",
      encryption_status: "OBSERVED",
      dh_group: "19",
      dh_group_name: "DH-Group-19 (ECP-256)",
      pfs: true,
      replay_protection: true,
      sa_lifetime: 3600,
      overall_score: 100,
      posture_grade: "A+",
      findings_count: 0,
      critical_findings_count: 0,
      anomaly_count: 0,
      has_drift: false,
      drift_severity: "None",
    };

    const exp: ExposureClock = {
      tunnel_id: tunnelId,
      security_state: "HEALTHY",
      reference_time: snap.timestamp,
      duration_seconds: 0,
      duration_human: "00h 00m 00s (Healthy)",
      affected_sas: 0,
      security_transitions: 0,
      risk_score_start: 100,
      risk_score_current: 100,
      disclaimer: "No configuration degradation detected at this point.",
    };

    const forecast: RiskForecast = {
      tunnel_id: tunnelId,
      current_state: "COMPLIANT",
      trend: "STABLE",
      forecast_window: "48h",
      confidence: 0.96,
      risk_factors: ["Hardened AEAD cryptographic suite verified", "Perfect Forward Secrecy enforced"],
      supporting_events: [],
      disclaimer: "Deterministic forecast based on observed parameter trends.",
    };

    return {
      index: i,
      label: `T${i}`,
      timestamp: snap.timestamp,
      snapshot: snap,
      events_at_this_point: [],
      exposure: exp,
      forecast,
      risk_graph: emptyGraph,
    };
  });

  // T4 degraded frame
  const t4Snap: VPNStateSnapshot = {
    analysis_id: analysisId,
    tunnel_id: tunnelId,
    sequence_index: 4,
    label: "T4",
    timestamp: new Date(now).toISOString(),
    dataset_type: "Controlled laboratory dataset",
    filename: "config_drift_vpn.pcap",
    ike_version: "IKEv2",
    ike_version_status: "OBSERVED",
    encryption: "AES-CBC-128",
    encryption_status: "OBSERVED",
    dh_group: "14",
    dh_group_name: "DH-Group-14 (MODP-2048)",
    pfs: false,
    replay_protection: true,
    sa_lifetime: 3600,
    overall_score: 82,
    posture_grade: "B",
    findings_count: 3,
    critical_findings_count: 0,
    anomaly_count: 0,
    has_drift: true,
    drift_severity: "High",
  };

  const t4Exp: ExposureClock = {
    tunnel_id: tunnelId,
    security_state: "DEGRADED",
    degradation_started_at: t4Snap.timestamp,
    reference_time: t4Snap.timestamp,
    duration_seconds: 13702,
    duration_human: "03h 48m 22s",
    affected_sas: 3,
    security_transitions: 1,
    risk_score_start: 100,
    risk_score_current: 82,
    disclaimer: "Active exposure window detected due to configuration downgrade.",
  };

  const t4Forecast: RiskForecast = {
    tunnel_id: tunnelId,
    current_state: "DEGRADED",
    trend: "ESCALATING",
    forecast_window: "48h",
    confidence: 0.91,
    risk_factors: ["Silent downgrade to AES-CBC (padding oracle exposure)", "PFS deactivated on Child SAs"],
    supporting_events: ["evt-drift-enc", "evt-drift-score"],
    disclaimer: "Deterministic forecast based on observed parameter trends.",
  };

  const t4Events: SecurityEvent[] = [
    {
      event_id: "evt-drift-enc",
      tunnel_id: tunnelId,
      analysis_id: analysisId,
      timestamp: t4Snap.timestamp,
      event_type: "CONFIGURATION_CHANGE",
      severity: "Medium",
      source: "fingerprint_diff",
      previous_value: "AES-256-GCM-16",
      current_value: "AES-CBC-128",
      evidence: "Cipher regressed from AES-GCM AEAD to CBC mode.",
      affected_component: "encryption",
      confidence: 0.95,
    },
    {
      event_id: "evt-drift-score",
      tunnel_id: tunnelId,
      analysis_id: analysisId,
      timestamp: t4Snap.timestamp,
      event_type: "RISK_SCORE_CHANGE",
      severity: "Medium",
      source: "risk_scorer",
      previous_value: "100",
      current_value: "82",
      evidence: "Score reduced from 100 to 82 (-18 penalty).",
      affected_component: "risk_score",
      confidence: 1.0,
    },
  ];

  frames.push({
    index: 4,
    label: "T4",
    timestamp: t4Snap.timestamp,
    snapshot: t4Snap,
    events_at_this_point: t4Events,
    exposure: t4Exp,
    forecast: t4Forecast,
    risk_graph: emptyGraph,
  });

  return {
    tunnel_id: tunnelId,
    frames,
    is_simulated: true,
    simulation_label: "CONTROLLED LABORATORY SIMULATION",
  };
}