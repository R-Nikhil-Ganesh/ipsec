import {
  AnalysisDetailResponse,
  DemoSample,
  WhatIfRequest,
  WhatIfResult,
} from "../types";

const API_BASE = "/api";

export async function uploadPcap(file: File): Promise<AnalysisDetailResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/analyze/pcap`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Upload failed" }));
    throw new Error(errorData.detail || "Failed to analyze PCAP");
  }

  return res.json();
}

export async function getAnalysis(id: string): Promise<AnalysisDetailResponse> {
  const res = await fetch(`${API_BASE}/analysis/${id}`);
  if (!res.ok) {
    throw new Error("Failed to fetch analysis details");
  }
  return res.json();
}

export async function listAnalyses(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/analyses`);
  if (!res.ok) {
    throw new Error("Failed to fetch past analyses");
  }
  return res.json();
}

export async function listDemoSamples(): Promise<DemoSample[]> {
  const res = await fetch(`${API_BASE}/demo/samples`);
  if (!res.ok) {
    throw new Error("Failed to fetch demo samples");
  }
  return res.json();
}

export async function loadDemoSample(sampleId: string): Promise<AnalysisDetailResponse> {
  const res = await fetch(`${API_BASE}/demo/load/${sampleId}`, {
    method: "POST",
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: "Demo load failed" }));
    throw new Error(errorData.detail || "Failed to load demo scenario");
  }

  return res.json();
}

export async function simulateHardening(
  req: WhatIfRequest,
  analysisId?: string
): Promise<WhatIfResult> {
  const url = analysisId
    ? `${API_BASE}/simulate?analysis_id=${encodeURIComponent(analysisId)}`
    : `${API_BASE}/simulate`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });

  if (!res.ok) {
    throw new Error("Simulation failed");
  }

  return res.json();
}

export function getExecutiveReportUrl(id: string): string {
  return `${API_BASE}/reports/${id}/executive`;
}

export function getTechnicalReportUrl(id: string): string {
  return `${API_BASE}/reports/${id}/technical`;
}

export function getPdfReportUrl(id: string, type: "executive" | "technical" = "technical"): string {
  return `${API_BASE}/reports/${id}/pdf?type=${type}`;
}
