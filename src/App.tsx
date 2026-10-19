import { useState, useCallback, useEffect, useLayoutEffect, useMemo, useRef, lazy, Suspense } from 'react';
import { flushSync } from 'react-dom';
import type { DetectedIoc } from './types/ioc';
import type { Workflow } from './types/workflow';
import type { Tool } from './types/tool';
import type { AnalysisResponse } from './types/analysis';
import { IocInput } from './components/IocInput';
import { AnalysisBar } from './components/WorkflowTiles';
import { ToolPanel } from './components/ToolPanel';
import { AutoAnalysisPanel } from './components/AutoAnalysisPanel';
import type { AutoAnalysisPanelHandle } from './components/AutoAnalysisPanel';
import { AppShell } from './components/AppShell';
import { CaseWorkspace } from './components/CaseWorkspace';
import { CommandPalette } from './components/CommandPalette';
import { loadCases } from './lib/cases';
import { STORAGE_KEYS, writeRaw } from './lib/storage';
import type { CaseRecord } from './types/case';
import type { Tab } from './components/AppShell';
import { checkBackendHealth } from './lib/apiClient';
import { fetchCustomTools, saveCustomTools, loadHiddenToolIds, toggleHiddenToolId } from './lib/toolsStorage';
import { loadFavorites, saveFavorites } from './lib/favorites';
import { detectIoc } from './lib/detectIoc';
import { isWorkflowEnabled } from './lib/workflows';
import { loadHistory, saveSearch, removeEntry, clearHistory } from './lib/searchHistory';
import type { HistoryEntry } from './lib/searchHistory';
import toolsData from './data/tools.json';
import workflowsData from './data/workflows.json';

// Pages other than Investigate load on first visit to keep the initial bundle small
const CasesPanel = lazy(() => import('./components/CasesPanel').then(m => ({ default: m.CasesPanel })));
const BulkExtractPanel = lazy(() => import('./components/BulkExtractPanel').then(m => ({ default: m.BulkExtractPanel })));
const BatchTriagePanel = lazy(() => import('./components/BatchTriagePanel').then(m => ({ default: m.BatchTriagePanel })));
const DefangPanel = lazy(() => import('./components/DefangPanel').then(m => ({ default: m.DefangPanel })));
const ConfigCheckPanel = lazy(() => import('./components/ConfigCheckPanel').then(m => ({ default: m.ConfigCheckPanel })));
const ApiKeysPanel = lazy(() => import('./components/ApiKeysPanel').then(m => ({ default: m.ApiKeysPanel })));
const ThreatFeedPanel = lazy(() => import('./components/ThreatFeedPanel').then(m => ({ default: m.ThreatFeedPanel })));
const AboutPanel = lazy(() => import('./components/AboutPanel').then(m => ({ default: m.AboutPanel })));
const SearchHistoryPanel = lazy(() => import('./components/SearchHistoryPanel').then(m => ({ default: m.SearchHistoryPanel })));
const ToolsManagementPanel = lazy(() => import('./components/ToolsManagementPanel').then(m => ({ default: m.ToolsManagementPanel })));

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
      writeRaw(STORAGE_KEYS.theme, next ? 'dark' : 'light');
      return next;
    });
  }, []);

  const [paletteOpen, setPaletteOpen] = useState(false);

  // ⌘K / Ctrl+K opens the command palette from anywhere, including inside inputs
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(v => !v);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
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

  // Results only count for the indicator they were produced for, so stale data never
  // shows under a new IOC. (Derived rather than cleared in an effect, which raced
  // with loading a saved analysis from History or a case.)
  const currentResults = analysisResults && analysisResults.ioc.normalised === ioc?.normalised ? analysisResults : null;

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
      if (!isWorkflowEnabled(selectedWorkflow, detected).enabled) setSelectedWorkflow(null);
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
        return isWorkflowEnabled(prev, detected).enabled ? prev : null;
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

  // ── Cases ───────────────────────────────────────────────────────────
  const [cases, setCases] = useState<CaseRecord[]>(() => loadCases());
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const activeCase = cases.find(c => c.id === activeCaseId) ?? null;

  // Investigating a different indicator detaches the open case
  useEffect(() => {
    if (activeCase && activeCase.ioc.normalised !== ioc?.normalised) setActiveCaseId(null);
  }, [ioc?.normalised]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCaseSaved = useCallback((saved: CaseRecord, all: CaseRecord[]) => {
    setCases(all);
    setActiveCaseId(saved.id);
  }, []);

  const handleOpenCase = useCallback((c: CaseRecord) => {
    setIoc(detectIoc(c.ioc.original));
    setPrefillIoc(c.ioc.original);
    setSelectedWorkflow(workflows.find(w => w.id === c.workflowId) ?? null);
    setAnalysisResults(c.analysis);
    setHistoryPreload(c.analysis);
    setActiveCaseId(c.id);
    setActiveTab('single');
  }, []);

  // Load an indicator into Investigate without running analysis
  const handleLoadIndicator = useCallback((value: string) => {
    setIoc(detectIoc(value));
    setPrefillIoc(value);
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
      onOpenPalette={() => setPaletteOpen(true)}
    >
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        cases={cases}
        onNavigate={setActiveTab}
        onInvestigate={handleLoadIndicator}
        onOpenCase={handleOpenCase}
      />
      {activeTab === 'single' && (
        <div className="space-y-4">
          <IocInput
            onDetect={handleDetect}
            onReset={handleReset}
            onSubmit={handleRunAnalysis}
            initialValue={ioc?.original}
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
            hasAnalysisResult={currentResults !== null}
            backendOnline={backendOnline}
          />
          <AutoAnalysisPanel
            ref={panelRef}
            ioc={ioc}
            workflowId={selectedWorkflow?.id ?? null}
            onComplete={handleAnalysisComplete}
            onPivot={handleInvestigate}
            preloadResult={historyPreload}
            onLoadingChange={setAnalysisLoading}
          />
          {/* Pivot tools stay available below the verdict once a workflow is chosen */}
          {(!currentResults || selectedWorkflow) && (
            <ToolPanel
              workflow={selectedWorkflow}
              ioc={ioc}
              tools={allTools}
              favorites={favorites}
              onToggleFavorite={handleToggleFavorite}
            />
          )}
          {ioc && (ioc.type !== 'unknown' || ioc.isEmailHeader) && (
            <CaseWorkspace
              ioc={ioc}
              workflow={selectedWorkflow}
              analysis={currentResults ?? activeCase?.analysis ?? null}
              activeCase={activeCase}
              onSaved={handleCaseSaved}
            />
          )}
        </div>
      )}

      <Suspense fallback={<p className="text-xs text-fg-4 py-6">Loading…</p>}>
      {activeTab === 'cases' && <CasesPanel cases={cases} workflows={workflows} onOpen={handleOpenCase} onChange={setCases} />}
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
      </Suspense>
    </AppShell>
  );
}
