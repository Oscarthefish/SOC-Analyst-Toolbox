import { useState, useCallback, useEffect } from 'react';
import type { DetectedIoc } from './types/ioc';
import type { Workflow } from './types/workflow';
import type { Tool } from './types/tool';
import type { AnalysisResponse } from './types/analysis';
import { IocInput } from './components/IocInput';
import { WorkflowTiles } from './components/WorkflowTiles';
import { ToolPanel } from './components/ToolPanel';
import { BulkExtractPanel } from './components/BulkExtractPanel';
import { BatchTriagePanel } from './components/BatchTriagePanel';
import { DefangPanel } from './components/DefangPanel';
import { ConfigCheckPanel } from './components/ConfigCheckPanel';
import { AutoAnalysisPanel } from './components/AutoAnalysisPanel';
import { AnalysisResultsPanel } from './components/AnalysisResultsPanel';
import { ApiKeysPanel } from './components/ApiKeysPanel';
import { ThreatFeedPanel } from './components/ThreatFeedPanel';
import { AboutPanel } from './components/AboutPanel';
import { checkBackendHealth } from './lib/apiClient';
import { loadFavorites, saveFavorites } from './lib/favorites';
import toolsData from './data/tools.json';
import workflowsData from './data/workflows.json';

type Tab = 'single' | 'bulk' | 'batch' | 'defang' | 'config' | 'apikeys' | 'threatfeed' | 'about';

const TAB_LABELS: Record<Tab, string> = {
  single:    'Single IOC',
  bulk:      'Bulk Extract',
  batch:     'Batch Triage',
  defang:    'Defang / Refang',
  config:    'Config Check',
  apikeys:   'API Keys',
  threatfeed:'Threat Feed',
  about:     'About',
};

const builtinTools = toolsData as Tool[];
const workflows = workflowsData as Workflow[];

let customTools: Tool[] = [];
let customToolCount = 0;
try {
  const modPath = './data/customTools' + '.json';
  const mod = await import(/* @vite-ignore */ modPath).catch(() => null);
  if (mod && Array.isArray(mod.default)) {
    customTools = mod.default as Tool[];
    customToolCount = customTools.length;
  }
} catch { /* no custom tools */ }

const allTools: Tool[] = [...builtinTools, ...customTools];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('single');
  const [backendOnline, setBackendOnline] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function check() {
      const result = await checkBackendHealth();
      if (!cancelled) setBackendOnline(result !== null);
    }
    void check();
    const interval = setInterval(() => { void check(); }, 30_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  const [ioc, setIoc] = useState<DetectedIoc | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(null);
  const [favorites, setFavorites] = useState<Set<string>>(() => loadFavorites());
  const [prefillIoc, setPrefillIoc] = useState<string | undefined>(undefined);
  const [analysisResults, setAnalysisResults] = useState<AnalysisResponse | null>(null);
  const [autoRunAnalysis, setAutoRunAnalysis] = useState(false);

  // Clear results whenever the IOC changes so stale data never shows under a new IOC
  useEffect(() => {
    setAnalysisResults(null);
  }, [ioc?.normalised]);

  const handleToggleFavorite = useCallback((toolId: string) => {
    setFavorites(prev => {
      const next = new Set(prev);
      if (next.has(toolId)) next.delete(toolId); else next.add(toolId);
      saveFavorites(next);
      return next;
    });
  }, []);

  const handleDetect = useCallback((detected: DetectedIoc | null) => {
    setIoc(detected);
    if (detected && selectedWorkflow) {
      const supported =
        selectedWorkflow.allowedInputTypes.includes(detected.type) ||
        (detected.type === 'url' && selectedWorkflow.allowedInputTypes.includes('domain'));
      if (!supported) setSelectedWorkflow(null);
    }
  }, [selectedWorkflow]);

  const handleReset = useCallback(() => {
    setIoc(null);
    setSelectedWorkflow(null);
    setPrefillIoc(undefined);
    setAnalysisResults(null);
    setAutoRunAnalysis(false);
  }, []);

  const handleWorkflowSelect = useCallback((workflow: Workflow) => {
    setSelectedWorkflow(prev => prev?.id === workflow.id ? null : workflow);
  }, []);

  const handleInvestigate = useCallback((iocValue: string) => {
    setAutoRunAnalysis(true);
    setPrefillIoc(iocValue);
    setActiveTab('single');
  }, []);

  const handleAutoRunConsumed = useCallback(() => {
    setAutoRunAnalysis(false);
  }, []);

  const handleAnalysisComplete = useCallback((r: AnalysisResponse | null) => {
    setAnalysisResults(r);
  }, []);

  const isSensitiveUrl = ioc?.isSensitiveUrl ?? false;

  return (
    <div className="min-h-screen bg-[#f4f5f7]" style={{ fontFamily: 'IBM Plex Sans, system-ui, sans-serif' }}>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-20 bg-white border-b border-[#e4e7ec]" style={{ boxShadow: '0 1px 2px rgba(16,24,40,.04)' }}>
        <div className="max-w-[1340px] mx-auto px-5 h-14 flex items-center justify-between">
          {/* Logo + name */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-[8px] bg-[#101828] flex items-center justify-center shrink-0">
              <svg className="w-4.5 h-4.5 text-white" style={{ width: 18, height: 18 }} fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <div>
              <p className="text-[15px] font-bold text-[#101828] leading-none">SOC Analyst Toolbox</p>
              <p className="text-[11px] text-[#98a2b3] leading-none mt-0.5">IOC pivot &amp; investigation</p>
            </div>
          </div>

          {/* Local-only pill */}
          <div className="flex items-center gap-1.5 h-7 px-3 rounded-full bg-[#ecfdf3] border border-[#abefc6]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#079455] animate-pulse" />
            <span className="text-[11px] font-semibold text-[#067647]">Local only</span>
          </div>
        </div>

        {/* Tab bar */}
        <div className="max-w-[1340px] mx-auto px-5">
          <nav className="flex -mb-px overflow-x-auto">
            {(Object.keys(TAB_LABELS) as Tab[]).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2.5 text-[13px] whitespace-nowrap border-b-2 transition-colors font-medium ${
                  activeTab === tab
                    ? 'border-[#1570ef] text-[#101828] font-semibold'
                    : 'border-transparent text-[#667085] hover:text-[#344054]'
                }`}
              >
                {TAB_LABELS[tab]}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* ── Privacy notice ──────────────────────────────────────────────── */}
      <div className="max-w-[1340px] mx-auto px-5 pt-3">
        <div className="flex items-center gap-2.5 px-3.5 py-2 bg-[#fffaeb] border border-[#fedf89] rounded-lg text-xs text-[#b54708]">
          <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>
            API calls go through the local backend only. External tool links may submit your IOC to third-party services — check the <strong>Passive / Submits IOC</strong> badge before opening.
          </span>
        </div>
      </div>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <main className="max-w-[1340px] mx-auto px-5 py-4">

        {/* Single IOC tab */}
        {activeTab === 'single' && (
          <div className="space-y-4">
            {/* Command bar (full width) */}
            <IocInput
              onDetect={handleDetect}
              onReset={handleReset}
              prefillValue={prefillIoc}
            />

            {/* Main grid: left column + sticky right rail */}
            <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 444px', alignItems: 'start' }}>

              {/* Left column */}
              <div className="space-y-4 min-w-0">
                <WorkflowTiles
                  ioc={ioc}
                  workflows={workflows}
                  selectedWorkflow={selectedWorkflow}
                  onSelect={handleWorkflowSelect}
                />
                <ToolPanel
                  workflow={selectedWorkflow}
                  ioc={ioc}
                  tools={allTools}
                  favorites={favorites}
                  onToggleFavorite={handleToggleFavorite}
                />
                {analysisResults && (
                  <AnalysisResultsPanel
                    response={analysisResults}
                    onPivot={handleInvestigate}
                  />
                )}
              </div>

              {/* Right rail — sticky */}
              <div className="sticky" style={{ top: '84px' }}>
                <AutoAnalysisPanel
                  ioc={ioc}
                  workflowId={selectedWorkflow?.id ?? null}
                  onComplete={handleAnalysisComplete}
                  onPivot={handleInvestigate}
                  autoRun={autoRunAnalysis}
                  onAutoRunConsumed={handleAutoRunConsumed}
                />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'bulk' && <BulkExtractPanel onInvestigate={handleInvestigate} />}
        {activeTab === 'batch' && <BatchTriagePanel onInvestigate={handleInvestigate} />}
        {activeTab === 'defang' && <DefangPanel />}
        {activeTab === 'config' && <ConfigCheckPanel tools={allTools} customToolCount={customToolCount} />}
        {activeTab === 'apikeys' && <ApiKeysPanel backendOnline={backendOnline} />}
        {activeTab === 'threatfeed' && <ThreatFeedPanel />}
        {activeTab === 'about' && <AboutPanel />}
      </main>

      <footer className="max-w-[1340px] mx-auto px-5 py-6 mt-4 border-t border-[#e4e7ec]">
        <p className="text-xs text-[#98a2b3]">SOC Analyst Toolbox · Local backend · No telemetry</p>
      </footer>
    </div>
  );
}
