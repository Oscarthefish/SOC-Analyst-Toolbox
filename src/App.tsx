import { useState, useCallback, useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import { flushSync } from 'react-dom';
import type { DetectedIoc } from './types/ioc';
import type { Workflow } from './types/workflow';
import type { Tool } from './types/tool';
import type { AnalysisResponse } from './types/analysis';
import { IocInput } from './components/IocInput';
import { AnalysisBar } from './components/WorkflowTiles';
import { ToolPanel } from './components/ToolPanel';
import { BulkExtractPanel } from './components/BulkExtractPanel';
import { BatchTriagePanel } from './components/BatchTriagePanel';
import { DefangPanel } from './components/DefangPanel';
import { ConfigCheckPanel } from './components/ConfigCheckPanel';
import { AutoAnalysisPanel } from './components/AutoAnalysisPanel';
import type { AutoAnalysisPanelHandle } from './components/AutoAnalysisPanel';
import { AnalysisResultsPanel } from './components/AnalysisResultsPanel';
import { ApiKeysPanel } from './components/ApiKeysPanel';
import { ThreatFeedPanel } from './components/ThreatFeedPanel';
import { AboutPanel } from './components/AboutPanel';
import { SearchHistoryPanel } from './components/SearchHistoryPanel';
import { ToolsManagementPanel } from './components/ToolsManagementPanel';
import { AppShell } from './components/AppShell';
import type { Tab } from './components/AppShell';
import { checkBackendHealth } from './lib/apiClient';
import { fetchCustomTools, saveCustomTools, loadHiddenToolIds, toggleHiddenToolId } from './lib/toolsStorage';
import { loadFavorites, saveFavorites } from './lib/favorites';
import { detectIoc } from './lib/detectIoc';
import { loadHistory, saveSearch, removeEntry, clearHistory } from './lib/searchHistory';
import type { HistoryEntry } from './lib/searchHistory';
import toolsData from './data/tools.json';
import workflowsData from './data/workflows.json';

const builtinTools = toolsData as Tool[];
const workflows = workflowsData as Workflow[];


export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('single');
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [customTools, setCustomTools] = useState<Tool[]>([]);
  const [hiddenToolIds, setHiddenToolIds] = useState<Set<string>>(() => loadHiddenToolIds());
  const [toolsSaving, setToolsSaving] = useState(false);
  // index.html applies the initial theme before first paint (stored choice, else OS preference)
  const [isDark, setIsDark] = useState<boolean>(() => document.documentElement.classList.contains('dark'));

  useLayoutEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
  }, [isDark]);

  const handleToggleTheme = useCallback(() => {
    setIsDark(prev => {
      const next = !prev;
      try { localStorage.setItem('theme', next ? 'dark' : 'light'); } catch { /* ignore */ }
      return next;
    });
  }, []);

  // "/" jumps to the indicator input from anywhere on the Investigate page
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
      e.preventDefault();
      setActiveTab('single');
      requestAnimationFrame(() => document.getElementById('ioc-input')?.focus());
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

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

  useEffect(() => {
    void fetchCustomTools().then(tools => setCustomTools(tools));
  }, []);

  const allTools = useMemo<Tool[]>(() => {
    const combined = [...builtinTools, ...customTools];
    return hiddenToolIds.size === 0 ? combined : combined.filter(t => !hiddenToolIds.has(t.id));
  }, [customTools, hiddenToolIds]);

  const handleSaveCustomTools = useCallback(async (tools: Tool[]) => {
    setToolsSaving(true);
    const ok = await saveCustomTools(tools);
    if (ok) setCustomTools(tools);
    setToolsSaving(false);
  }, []);

  const handleToggleHidden = useCallback((id: string) => {
    setHiddenToolIds(prev => toggleHiddenToolId(id, prev));
  }, []);

  const [ioc, setIoc] = useState<DetectedIoc | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(null);
  const [favorites, setFavorites] = useState<Set<string>>(() => loadFavorites());
  const [prefillIoc, setPrefillIoc] = useState<string | undefined>(undefined);
  const [analysisResults, setAnalysisResults] = useState<AnalysisResponse | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const panelRef = useRef<AutoAnalysisPanelHandle>(null);
  const [searchHistory, setSearchHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [historyPreload, setHistoryPreload] = useState<AnalysisResponse | null>(null);

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
  }, []);

  const handleWorkflowSelect = useCallback((workflow: Workflow) => {
    setSelectedWorkflow(prev => prev?.id === workflow.id ? null : workflow);
  }, []);

  const handleInvestigate = useCallback((iocValue: string) => {
    const detected = detectIoc(iocValue);
    // flushSync forces the new IOC and workflow to commit synchronously so that
    // by the time panelRef.current.run() is called the panel already has the
    // correct props (including the layout-effect reset of activeRunIdRef).
    flushSync(() => {
      setIoc(detected);
      setSelectedWorkflow(prev => {
        if (!prev || !detected) return prev;
        const supported =
          prev.allowedInputTypes.includes(detected.type) ||
          (detected.type === 'url' && prev.allowedInputTypes.includes('domain'));
        return supported ? prev : null;
      });
      setPrefillIoc(iocValue);
      setActiveTab('single');
    });
    panelRef.current?.run(false);
  }, []);

  const handleRunAnalysis = useCallback(() => {
    panelRef.current?.run(false);
  }, []);

  const handleForceRunAnalysis = useCallback(() => {
    panelRef.current?.run(true);
  }, []);

  const handlePrefillConsumed = useCallback(() => {
    setPrefillIoc(undefined);
  }, []);

  const handleAnalysisComplete = useCallback((r: AnalysisResponse | null) => {
    setAnalysisResults(r);
    if (r) setSearchHistory(saveSearch(r.ioc, selectedWorkflow?.id ?? null, r));
  }, [selectedWorkflow]);

  const handleHistoryLoad = useCallback((entry: HistoryEntry) => {
    const detected = detectIoc(entry.ioc.original);
    setIoc(detected);
    setPrefillIoc(entry.ioc.original);
    setAnalysisResults(entry.result);
    setHistoryPreload(entry.result);
    setActiveTab('single');
  }, []);

  const handleHistoryRemove = useCallback((id: string) => {
    setSearchHistory(removeEntry(id));
  }, []);

  const handleHistoryClear = useCallback(() => {
    setSearchHistory(clearHistory());
  }, []);

  return (
    <AppShell
      activeTab={activeTab}
      onTabChange={setActiveTab}
      backendOnline={backendOnline}
      isDark={isDark}
      onToggleTheme={handleToggleTheme}
    >
      {activeTab === 'single' && (
        <div className="space-y-4">
          <IocInput
            onDetect={handleDetect}
            onReset={handleReset}
            onSubmit={handleRunAnalysis}
            prefillValue={prefillIoc}
            onPrefillConsumed={handlePrefillConsumed}
          />
          <AnalysisBar
            ioc={ioc}
            workflows={workflows}
            selectedWorkflow={selectedWorkflow}
            onSelectWorkflow={handleWorkflowSelect}
            onRunAnalysis={handleRunAnalysis}
            onForceRunAnalysis={handleForceRunAnalysis}
            analysisLoading={analysisLoading}
            hasAnalysisResult={analysisResults !== null}
            backendOnline={backendOnline}
          />
          <AutoAnalysisPanel
            ref={panelRef}
            ioc={ioc}
            workflowId={selectedWorkflow?.id ?? null}
            onComplete={handleAnalysisComplete}
            onPivot={handleInvestigate}
            preloadResult={historyPreload}
            hideHeader
            onLoadingChange={setAnalysisLoading}
          />
          {analysisResults && (
            <AnalysisResultsPanel
              response={analysisResults}
              onPivot={handleInvestigate}
            />
          )}
          {/* Pivot tools stay available below the verdict once a workflow is chosen */}
          {(!analysisResults || selectedWorkflow) && (
            <ToolPanel
              workflow={selectedWorkflow}
              ioc={ioc}
              tools={allTools}
              favorites={favorites}
              onToggleFavorite={handleToggleFavorite}
            />
          )}
        </div>
      )}

      {activeTab === 'bulk' && <BulkExtractPanel onInvestigate={handleInvestigate} />}
      {activeTab === 'batch' && <BatchTriagePanel onInvestigate={handleInvestigate} />}
      {activeTab === 'defang' && <DefangPanel />}
      {activeTab === 'config' && <ConfigCheckPanel tools={allTools} customToolCount={customTools.length} />}
      {activeTab === 'apikeys' && <ApiKeysPanel backendOnline={backendOnline === true} />}
      {activeTab === 'threatfeed' && <ThreatFeedPanel />}
      {activeTab === 'tools' && (
        <ToolsManagementPanel
          builtinTools={builtinTools}
          customTools={customTools}
          hiddenToolIds={hiddenToolIds}
          saving={toolsSaving}
          onSaveCustomTools={handleSaveCustomTools}
          onToggleHidden={handleToggleHidden}
        />
      )}
      {activeTab === 'history' && (
        <SearchHistoryPanel
          entries={searchHistory}
          onLoad={handleHistoryLoad}
          onRemove={handleHistoryRemove}
          onClear={handleHistoryClear}
        />
      )}
      {activeTab === 'about' && <AboutPanel />}
    </AppShell>
  );
}
