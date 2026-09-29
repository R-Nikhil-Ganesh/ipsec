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
  const [activeTab, setActiveTab] = useState<
    "overview" | "findings" | "graph" | "whatif" | "traffic" | "drift"
  >("overview");

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

            {/* Navigation Tabs */}
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 overflow-x-auto">
              <button
                onClick={() => setActiveTab("overview")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "overview"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Layers className="w-4 h-4" />
                <span>Digital Twin & Overview</span>
              </button>

              <button
                onClick={() => setActiveTab("findings")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "findings"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Shield className="w-4 h-4" />
                <span>Security Findings ({analysis.findings.length})</span>
              </button>

              <button
                onClick={() => setActiveTab("graph")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "graph"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <GitBranch className="w-4 h-4" />
                <span>Attack & Risk Path Graph</span>
              </button>

              <button
                onClick={() => setActiveTab("whatif")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "whatif"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Sliders className="w-4 h-4" />
                <span>What-If Simulator</span>
              </button>

              <button
                onClick={() => setActiveTab("traffic")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "traffic"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Traffic & Privacy</span>
              </button>

              <button
                onClick={() => setActiveTab("drift")}
                className={`flex items-center space-x-1.5 px-3.5 py-2 text-xs font-bold rounded-lg transition-all ${
                  activeTab === "drift"
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
              >
                <GitCompare className="w-4 h-4" />
                <span>
                  Config Drift {analysis.drift.has_drift && "⚠️"}
                </span>
              </button>
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
