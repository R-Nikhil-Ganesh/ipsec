export interface PeerInfo {
  initiator_ip?: string;
  responder_ip?: string;
  initiator_port?: number;
  responder_port?: number;
  ip_version: string;
  spi_initiator?: string;
  spi_responder?: string;
  esp_spis: string[];
}

export interface VPNFingerprint {
  protocol: string;
  ike_version?: string | null;
  ike_version_status: string;
  mode?: string | null;
  mode_status: string; // "OBSERVED" | "INFERRED" | "UNKNOWN"
  encryption?: string | null;
  encryption_status: string;
  integrity?: string | null;
  integrity_status: string;
  authentication?: string | null;
  authentication_status: string;
  dh_group?: string | null;
  dh_group_name?: string | null;
  dh_group_status: string;
  pfs?: boolean | null;
  pfs_status: string;
  replay_protection?: boolean | null;
  replay_protection_status: string;
  sa_lifetime?: number | null;
  sa_lifetime_status: string;
  nat_traversal?: boolean | null;
  nat_traversal_status: string;
  ip_version?: string;
  confidence: number;
  evidence: Record<string, any>;
  peer_info?: PeerInfo;
}

export interface SecurityFinding {
  id: string;
  title: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  score_impact: number;
  evidence: string;
  confidence: number;
  why_it_matters: string;
  remediation: string;
  remediation_patch?: string | null;
}

export interface ScoreDeduction {
  finding_id: string;
  title: string;
  category: string;
  severity: string;
  penalty: number;
  reason: string;
}

export interface RiskScoreBreakdown {
  overall_score: number;
  posture_grade: string;
  base_score: number;
  total_penalty: number;
  category_scores: Record<string, number>;
  findings_count: Record<string, number>;
  score_deductions: ScoreDeduction[];
}

export interface TrafficClassification {
  traffic_type: string;
  confidence: number;
  basis: string;
  disclaimer: string;
  packet_count: number;
  byte_count: number;
  flow_duration_sec: number;
  avg_packet_size: number;
  packet_size_variance: number;
  inter_arrival_mean_ms: number;
  class_probabilities: Record<string, number>;
}

export interface AnomalyFinding {
  id: string;
  anomaly_detected: boolean;
  anomaly_type: string;
  severity: string;
  confidence: number;
  relevant_features: Record<string, any>;
  explanation: string;
  timestamp_range?: string;
}

export interface MetadataPrivacyFactor {
  name: string;
  value: string;
  impact: string;
  explanation: string;
}

export interface MetadataPrivacyAnalysis {
  metadata_exposure_score: number;
  risk_level: string;
  packet_size_variability: string;
  timing_regularity: string;
  directionality_ratio: number;
  burstiness_index: number;
  flow_duration: number;
  factors: MetadataPrivacyFactor[];
  privacy_recommendation: string;
}

export interface DriftChange {
  parameter: string;
  previous_value?: string | null;
  current_value?: string | null;
  severity: string;
  security_implication: string;
}

export interface ConfigurationDrift {
  has_drift: boolean;
  baseline_id?: string | null;
  baseline_name?: string | null;
  drift_detected_at?: string | null;
  changes: DriftChange[];
  drift_severity: string;
}

export interface RiskGraphNode {
  id: string;
  label: string;
  category: string;
  severity: string;
  details: string;
  timestamp?: string | null;
  confidence?: number | null;
  state?: string | null; // "Observed" | "Potential consequence" | "Requires investigation"
  source_event_id?: string | null;
}

export interface RiskGraphEdge {
  source: string;
  target: string;
  label: string;
  confidence?: number | null;
  state?: string | null;
}

export interface RiskPathGraph {
  nodes: RiskGraphNode[];
  edges: RiskGraphEdge[];
}

export interface PacketStatistics {
  total_packets: number;
  ipsec_packets: number;
  ike_packets: number;
  esp_packets: number;
  ah_packets: number;
  nat_t_packets: number;
  other_packets: number;
  duration_seconds: number;
  data_rate_kbps: number;
  packet_size_distribution: Record<string, number>;
  timeline_buckets: Array<{
    time_sec: number;
    packets: number;
    bytes: number;
    ike: number;
    esp: number;
  }>;
}

export interface AnalysisDetailResponse {
  id: string;
  filename: string;
  analyzed_at: string;
  status: string;
  dataset_type: string;
  fingerprint: VPNFingerprint;
  risk_score: RiskScoreBreakdown;
  findings: SecurityFinding[];
  traffic_classification: TrafficClassification;
  anomalies: AnomalyFinding[];
  metadata_privacy: MetadataPrivacyAnalysis;
  drift: ConfigurationDrift;
  risk_graph: RiskPathGraph;
  packet_stats: PacketStatistics;
}

export interface DemoSample {
  id: string;
  name: string;
  pcap: string;
  tag: string;
  description: string;
}

export interface WhatIfRequest {
  ike_version?: string;
  encryption?: string;
  integrity?: string;
  dh_group?: string;
  pfs?: boolean;
  replay_protection?: boolean;
  sa_lifetime?: number;
  mode?: string;
}

export interface WhatIfResult {
  current_score: number;
  projected_score: number;
  score_delta: number;
  current_grade: string;
  projected_grade: string;
  resolved_findings: SecurityFinding[];
  remaining_findings: SecurityFinding[];
  new_findings: SecurityFinding[];
  projected_breakdown: RiskScoreBreakdown;
  hardening_guidance: string[];
  config_snippet: string;
  disclaimer: string;
}

// ============================================================
// Temporal Security Twin
// ============================================================

export interface VPNStateSnapshot {
  analysis_id: string;
  tunnel_id: string;
  sequence_index: number;
  label: string;
  timestamp: string;
  dataset_type: string;
  filename: string;
  ike_version?: string | null;
  ike_version_status: string;
  encryption?: string | null;
  encryption_status: string;
  dh_group?: string | null;
  dh_group_name?: string | null;
  pfs?: boolean | null;
  replay_protection?: boolean | null;
  sa_lifetime?: number | null;
  overall_score: number;
  posture_grade: string;
  findings_count: number;
  critical_findings_count: number;
  anomaly_count: number;
  has_drift: boolean;
  drift_severity: string;
}

export interface SecurityEvent {
  event_id: string;
  tunnel_id: string;
  analysis_id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  source: string;
  previous_value?: string | null;
  current_value?: string | null;
  evidence: string;
  affected_component: string;
  confidence: number;
}

export interface CorrelatedSequence {
  sequence_id: string;
  label: string;
  interpretation: string;
  events: SecurityEvent[];
}

export interface SecurityTimeline {
  tunnel_id: string;
  snapshots: VPNStateSnapshot[];
  events: SecurityEvent[];
  correlated_sequences: CorrelatedSequence[];
  is_simulated: boolean;
  simulation_label?: string | null;
}

export interface ExposureClock {
  tunnel_id: string;
  security_state: string; // HEALTHY | DEGRADED | UNKNOWN
  degradation_started_at?: string | null;
  reference_time: string;
  duration_seconds: number;
  duration_human: string;
  affected_sas: number;
  security_transitions: number;
  risk_score_start?: number | null;
  risk_score_current: number;
  disclaimer: string;
}

export interface RiskForecast {
  tunnel_id: string;
  current_state: string;
  trend: string; // ESCALATING | IMPROVING | STABLE | INSUFFICIENT_DATA
  forecast_window: string;
  confidence: number;
  risk_factors: string[];
  supporting_events: string[];
  disclaimer: string;
}

export interface RemediationChange {
  parameter: string;
  from_value?: string | null;
  to_value?: string | null;
}

export interface RemediationPlan {
  plan_id: string;
  label: string;
  problem_summary: string;
  changes: RemediationChange[];
  whatif_request: WhatIfRequest;
  whatif_result: WhatIfResult;
  findings_resolved: number;
  findings_remaining: number;
  graph_nodes_removed: number;
  graph_edges_removed: number;
}

export interface RemediationComparison {
  analysis_id: string;
  current_score: number;
  current_grade: string;
  plans: RemediationPlan[];
}

export interface ReplayFrame {
  index: number;
  label: string;
  timestamp: string;
  snapshot: VPNStateSnapshot;
  events_at_this_point: SecurityEvent[];
  exposure: ExposureClock;
  forecast: RiskForecast;
  risk_graph: RiskPathGraph;
}

export interface IncidentReplay {
  tunnel_id: string;
  frames: ReplayFrame[];
  is_simulated: boolean;
  simulation_label?: string | null;
}
