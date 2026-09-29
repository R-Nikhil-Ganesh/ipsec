import React, { useState, useEffect } from "react";
import {
  Shield,
  Layers,
  FileText,
  Sliders,
  GitBranch,
  Activity,
  GitCompare,
  Zap,
  Upload,
  AlertCircle,
  EyeOff,
  Info,
  History,
} from "lucide-react";
import { AnalysisDetailResponse, DemoSample } from "./types";
import {
  listDemoSamples,
  loadDemoSample,
  uploadPcap,
} from "./services/api";

import { Navbar } from "./components/Navbar";
import { DemoSelector } from "./components/DemoSelector";
import { FileUpload } from "./components/FileUpload";
import { VPNOverviewCards } from "./components/VPNOverviewCards";
import { DigitalTwinView } from "./components/DigitalTwinView";
import { FindingsList } from "./components/FindingsList";
import { ScoreBreakdownCard } from "./components/ScoreBreakdownCard";
import { RiskGraphView } from "./components/RiskGraphView";
import { WhatIfSimulatorView } from "./components/WhatIfSimulatorView";
import { EncryptedTrafficView } from "./components/EncryptedTrafficView";
import { MetadataPrivacyView } from "./components/MetadataPrivacyView";
import { DriftView } from "./components/DriftView";
import { TrafficAnalyticsCharts } from "./components/TrafficAnalyticsCharts";
import { ReportsModal } from "./components/ReportsModal";
import { SecurityTimeline } from "./components/SecurityTimeline";
import { ExposureClock } from "./components/ExposureClock";
import { RiskForecastView } from "./components/RiskForecastView";
import { RemediationPlanner } from "./components/RemediationPlanner";
import { IncidentReplay } from "./components/IncidentReplay";

type TabId = "overview" | "findings" | "graph" | "whatif" | "traffic" | "drift" | "evolution";

interface TabConfig {
  id: TabId;
  step: number;
  label: string;
  icon: React.ElementType;
  description: string;
}

const TAB_CONFIG: TabConfig[] = [
  {
    id: "overview",
    step: 1,
    label: "Digital Twin & Overview",
    icon: Layers,
    description:
      "A plain-English model of the captured tunnel — protocol, mode, ciphers and key exchange — rebuilt from raw packets so you can see exactly what the VPN is configured to do.",
  },
  {
    id: "findings",
    step: 2,
    label: "Security Findings",
    icon: Shield,
    description:
      "Every issue the engine flagged, ranked by severity, with the RFC or best-practice reasoning behind each one — the 'what's wrong and why it matters' view.",
  },
  {
    id: "graph",
    step: 3,
    label: "Attack & Risk Path Graph",
    icon: GitBranch,
    description:
      "Turns the findings into a connected attack path, showing how a weakness could realistically be chained by an attacker to compromise the tunnel.",
  },
  {
    id: "whatif",
    step: 4,
    label: "What-If Simulator",
    icon: Sliders,
    description:
      "An interactive sandbox to toggle hardening changes (stronger ciphers, PFS, etc.) and instantly see the projected impact on the security score.",
  },
  {
    id: "traffic",
    step: 5,
    label: "Traffic & Privacy",
    icon: Activity,
    description:
      "Classifies encrypted traffic patterns and estimates what metadata (timing, size, endpoints) could leak about user activity even without decrypting payloads.",
  },
  {
    id: "drift",
    step: 6,
    label: "Config Drift",
    icon: GitCompare,
    description:
      "Compares the current configuration against an established baseline to catch silent regressions — settings that changed without anyone noticing.",
  },
  {
    id: "evolution",
    step: 7,
    label: "Security Evolution",
    icon: History,
    description:
      "The Temporal Security Twin: tracks how this tunnel's posture has changed across every observed snapshot, how long it has stayed degraded, where its risk trajectory is heading, and which remediation plan would fix it fastest.",
  },
];

export const App: React.FC = () => {
  const [analysis, setAnalysis] = useState<AnalysisDetailResponse | null>(null);
  const [demoSamples, setDemoSamples] = useState<DemoSample[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Modals
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [isDemoOpen, setIsDemoOpen] = useState<boolean>(false);
  const [isReportsOpen, setIsReportsOpen] = useState<boolean>(false);

  // Tabs
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const activeTabConfig = TAB_CONFIG.find((t) => t.id === activeTab)!;

  // Load initial demo samples and default to Configuration Drift Demo
  useEffect(() => {
    const init = async () => {
      try {
        const samples = await listDemoSamples();
        setDemoSamples(samples);
        // Automatically load Configuration Drift Demo (per demonstration flow Section 28)
        const defaultData = await loadDemoSample("config-drift");
        setAnalysis(defaultData);
      } catch (err: any) {
        console.error("Initialization failed", err);
        setErrorMsg("Could not connect to IPsec Sentinel backend. Ensure server is running on :8000.");
      } finally {
        setIsLoading(false);
      }
    };

    init();
  }, []);

  const handleSelectDemo = async (sampleId: string) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const data = await loadDemoSample(sampleId);
      setAnalysis(data);
      setIsDemoOpen(false);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to load demo scenario.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleUploadPcap = async (file: File) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const data = await uploadPcap(file);
      setAnalysis(data);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to analyze PCAP.");
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-200 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <Navbar
        currentFilename={analysis?.filename}
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenDemoLab={() => setIsDemoOpen(true)}
        onOpenReports={() => setIsReportsOpen(true)}
        isLoading={isLoading}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Error Banner */}
        {errorMsg && (
          <div className="p-4 bg-rose-950/40 border border-rose-500/50 rounded-xl flex items-center space-x-3 text-rose-300 text-xs shadow-lg">
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
            <div className="flex-1">
              <span className="font-bold">Error:</span> {errorMsg}
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-xs underline hover:text-white"
            >
              Dismiss
            </button>
          </div>
        )}

        {analysis ? (
          <>
            {/* Top Overview Cards & Drift Alert */}
            <VPNOverviewCards
              fingerprint={analysis.fingerprint}
              riskScore={analysis.risk_score}
              drift={analysis.drift}
              anomalies={analysis.anomalies}
              onOpenWhatIf={() => setActiveTab("whatif")}
              onOpenDrift={() => setActiveTab("drift")}
            />

            {/* Navigation Tabs — numbered to read as a guided walkthrough */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 overflow-x-auto">
                {TAB_CONFIG.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  const badge =
                    tab.id === "findings"
                      ? ` (${analysis.findings.length})`
                      : tab.id === "drift" && analysis.drift.has_drift
                      ? " ⚠️"
                      : "";
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`flex items-center space-x-2 px-3.5 py-2 text-xs font-bold rounded-lg transition-all whitespace-nowrap ${
                        isActive
                          ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent"
                      }`}
                    >
                      <span
                        className={`flex items-center justify-center w-4 h-4 rounded-full text-[9px] font-extrabold ${
                          isActive ? "bg-cyan-400 text-slate-950" : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {tab.step}
                      </span>
                      <Icon className="w-4 h-4" />
                      <span>
                        {tab.label}
                        {badge}
                      </span>
                    </button>
                  );
                })}
              </div>

              {/* Explainer banner — what this step shows and why it matters */}
              <div className="flex items-start space-x-2.5 px-4 py-2.5 bg-slate-900/60 border border-slate-800 rounded-lg text-xs text-slate-400">
                <Info className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
                <p>
                  <span className="font-bold text-slate-200">
                    Step {activeTabConfig.step} — {activeTabConfig.label}:
                  </span>{" "}
                  {activeTabConfig.description}
                </p>
              </div>
            </div>

            {/* TAB 1: Digital Twin & Overview */}
            {activeTab === "overview" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <DigitalTwinView
                  fingerprint={analysis.fingerprint}
                  stats={analysis.packet_stats}
                />
                <TrafficAnalyticsCharts stats={analysis.packet_stats} />
                <ScoreBreakdownCard riskScore={analysis.risk_score} />
              </div>
            )}

            {/* TAB 2: Security Findings */}
            {activeTab === "findings" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <FindingsList findings={analysis.findings} />
                <ScoreBreakdownCard riskScore={analysis.risk_score} />
              </div>
            )}

            {/* TAB 3: Attack / Risk Path Graph */}
            {activeTab === "graph" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <RiskGraphView graph={analysis.risk_graph} />
              </div>
            )}

            {/* TAB 4: What-If Hardening Simulator */}
            {activeTab === "whatif" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <WhatIfSimulatorView
                  currentFingerprint={analysis.fingerprint}
                  analysisId={analysis.id}
                />
              </div>
            )}

            {/* TAB 5: Encrypted Traffic & Privacy */}
            {activeTab === "traffic" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <EncryptedTrafficView traffic={analysis.traffic_classification} />
                <MetadataPrivacyView privacy={analysis.metadata_privacy} />
              </div>
            )}

            {/* TAB 6: Configuration Drift */}
            {activeTab === "drift" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <DriftView drift={analysis.drift} />
              </div>
            )}

            {/* TAB 7: Security Evolution — Temporal Security Twin */}
            {activeTab === "evolution" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <SecurityTimeline analysisId={analysis.id} />
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <ExposureClock analysisId={analysis.id} />
                  <RiskForecastView analysisId={analysis.id} />
                </div>
                <RemediationPlanner analysisId={analysis.id} />
                <IncidentReplay analysisId={analysis.id} />
              </div>
            )}
          </>
        ) : (
          <div className="py-20 text-center space-y-4">
            <Shield className="w-12 h-12 text-cyan-500 mx-auto animate-pulse" />
            <h2 className="text-xl font-bold text-white">Loading IPsec Sentinel Engine...</h2>
            <p className="text-sm text-slate-400">Initializing Scapy packet parsers and baseline definitions.</p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800 bg-slate-950/80 py-4 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>IPsec Sentinel — AI-Powered Defensive VPN Security Intelligence Platform</span>
          <span className="font-mono text-slate-400">
            Smart India Hackathon Prototype • RFC 7296 / RFC 4301 Standard
          </span>
        </div>
      </footer>

      {/* Modals */}
      <DemoSelector
        isOpen={isDemoOpen}
        onClose={() => setIsDemoOpen(false)}
        samples={demoSamples}
        onSelectSample={handleSelectDemo}
        isLoading={isLoading}
      />

      <FileUpload
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadFile={handleUploadPcap}
        isLoading={isLoading}
      />

      {analysis && (
        <ReportsModal
          isOpen={isReportsOpen}
          onClose={() => setIsReportsOpen(false)}
          analysisId={analysis.id}
          filename={analysis.filename}
        />
      )}
    </div>
  );
};

export default App;
