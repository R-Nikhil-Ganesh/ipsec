import React, { useState } from "react";
import { FileText, Download, ExternalLink, X, Shield, Wrench } from "lucide-react";
import { getExecutiveReportUrl, getTechnicalReportUrl, getPdfReportUrl } from "../services/api";

interface ReportsModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysisId: string;
  filename: string;
}

export const ReportsModal: React.FC<ReportsModalProps> = ({
  isOpen,
  onClose,
  analysisId,
  filename,
}) => {
  const [activeTab, setActiveTab] = useState<"executive" | "technical">("executive");

  if (!isOpen) return null;

  const execHtmlUrl = getExecutiveReportUrl(analysisId);
  const techHtmlUrl = getTechnicalReportUrl(analysisId);
  const pdfDownloadUrl = getPdfReportUrl(analysisId, activeTab);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-4xl w-full h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Security Assessment Reports</h2>
              <p className="text-xs text-slate-400">Target PCAP: {filename} • ID: {analysisId}</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Download PDF button */}
            <a
              href={pdfDownloadUrl}
              download
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow-md shadow-cyan-600/20 transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </a>

            {/* Open in new tab */}
            <a
              href={activeTab === "executive" ? execHtmlUrl : techHtmlUrl}
              target="_blank"
              rel="noreferrer"
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700 transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open HTML in Tab</span>
            </a>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 px-6">
          <button
            onClick={() => setActiveTab("executive")}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-bold border-b-2 transition-all ${
              activeTab === "executive"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Executive Report (CISO / Management)</span>
          </button>

          <button
            onClick={() => setActiveTab("technical")}
            className={`flex items-center space-x-2 py-3 px-4 text-xs font-bold border-b-2 transition-all ${
              activeTab === "technical"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>Technical Audit Report (Engineering / SOC)</span>
          </button>
        </div>

        {/* Embedded Report Frame */}
        <div className="flex-1 bg-white">
          <iframe
            src={activeTab === "executive" ? execHtmlUrl : techHtmlUrl}
            title="Security Report Preview"
            className="w-full h-full border-0"
          />
        </div>
      </div>
    </div>
  );
};
