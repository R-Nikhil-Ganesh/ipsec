import React, { useState, useRef } from "react";
import { Upload, FileUp, X, CheckCircle2, Loader2, AlertCircle } from "lucide-react";

interface FileUploadProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadFile: (file: File) => Promise<void>;
  isLoading: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  isOpen,
  onClose,
  onUploadFile,
  isLoading,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file: File) => {
    setErrorMsg(null);
    const validExts = [".pcap", ".pcapng", ".cap"];
    const hasValidExt = validExts.some((ext) => file.name.toLowerCase().endsWith(ext));
    if (!hasValidExt) {
      setErrorMsg("Please upload a valid packet capture file (.pcap, .pcapng, or .cap).");
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;
    try {
      await onUploadFile(selectedFile);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || "Upload and analysis failed.");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/80">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Upload PCAP / Live Capture</h2>
              <p className="text-xs text-slate-400">
                IPsec Sentinel parses headers, isolates IKE/ESP, and evaluates posture.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isLoading}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors disabled:opacity-50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6">
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleChange}
            className="hidden"
          />

          {!isLoading ? (
            <div>
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => inputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  dragActive
                    ? "border-cyan-400 bg-cyan-950/20"
                    : selectedFile
                    ? "border-emerald-500/50 bg-emerald-950/10"
                    : "border-slate-700 hover:border-slate-500 bg-slate-800/40"
                }`}
              >
                <div className="flex flex-col items-center space-y-3">
                  <div
                    className={`p-3 rounded-full ${
                      selectedFile ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {selectedFile ? <CheckCircle2 className="w-8 h-8" /> : <FileUp className="w-8 h-8" />}
                  </div>

                  <div>
                    {selectedFile ? (
                      <div>
                        <p className="text-sm font-semibold text-white">{selectedFile.name}</p>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {(selectedFile.size / 1024).toFixed(1)} KB • Ready for deep analysis
                        </p>
                      </div>
                    ) : (
                      <div>
                        <p className="text-sm font-semibold text-slate-200">
                          Click to select or drag & drop PCAP
                        </p>
                        <p className="text-xs text-slate-400 mt-1">
                          Supported formats: .pcap, .pcapng, .cap (Scapy Engine)
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {errorMsg && (
                <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-center space-x-2 text-rose-300 text-xs">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}

              <div className="mt-6 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={!selectedFile}
                  onClick={handleStartAnalysis}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-semibold rounded-lg shadow-md shadow-cyan-600/20 transition-all"
                >
                  Begin Analysis
                </button>
              </div>
            </div>
          ) : (
            /* Analysis Pipeline Progress Indicator */
            <div className="py-6 px-2 space-y-4">
              <div className="flex items-center space-x-3">
                <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Analyzing Packet Capture...</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Scapy layer parsing & ML classification pipeline
                  </p>
                </div>
              </div>

              <div className="space-y-2.5 pt-2">
                <div className="flex items-center space-x-2 text-xs text-cyan-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Extracting IP/UDP headers & identifying ESP / ISAKMP</span>
                </div>
                <div className="flex items-center space-x-2 text-xs text-cyan-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Reconstructing IKE Phase 1 / Phase 2 cryptographic proposals</span>
                </div>
                <div className="flex items-center space-x-2 text-xs text-cyan-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Evaluating compliance against NIST SP 800-77 Rev. 1 baseline</span>
                </div>
                <div className="flex items-center space-x-2 text-xs text-cyan-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Running Isolation Forest anomaly detector & flow classifier</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
