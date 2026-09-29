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
}

export interface RiskGraphEdge {
  source: string;
  target: string;
  label: string;
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
