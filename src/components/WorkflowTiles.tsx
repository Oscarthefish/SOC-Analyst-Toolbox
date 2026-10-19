import type { DetectedIoc } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import { isWorkflowEnabled } from '../lib/workflows';


// Feather/Lucide-style SVG icons for each workflow

function IconCrosshair() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="3" />
      <line x1="12" y1="2" x2="12" y2="5" /><line x1="12" y1="19" x2="12" y2="22" />
      <line x1="2" y1="12" x2="5" y2="12" /><line x1="19" y1="12" x2="22" y2="12" />
    </svg>
  );
}
function IconGlobe() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  );
}
function IconLink() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />
    </svg>
  );
}
function IconMail() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
      <polyline points="22,6 12,13 2,6" />
    </svg>
  );
}
function IconHash() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="9" x2="20" y2="9" /><line x1="4" y1="15" x2="20" y2="15" />
      <line x1="10" y1="3" x2="8" y2="21" /><line x1="16" y1="3" x2="14" y2="21" />
    </svg>
  );
}
function IconShare() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  );
}
function IconShield() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function IconEye() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
function IconFlag() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
      <line x1="4" y1="22" x2="4" y2="15" />
    </svg>
  );
}
function IconLock() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0110 0v4" />
    </svg>
  );
}
function IconRadio() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 010 8.49m-8.48-.01a6 6 0 010-8.49m11.31-2.82a10 10 0 010 14.14m-14.14 0a10 10 0 010-14.14" />
    </svg>
  );
}
function IconMailOpen() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21.5 7.5L12 13 2.5 7.5" />
      <path d="M2 7l10-5 10 5v11a2 2 0 01-2 2H4a2 2 0 01-2-2V7z" />
    </svg>
  );
}
function IconCve() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}
function IconBuilding() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M8 7h.01M12 7h.01M16 7h.01M8 11h.01M12 11h.01M16 11h.01M8 15h.01M12 15h.01" />
      <path d="M9 21v-4h6v4" />
    </svg>
  );
}

const WORKFLOW_ICONS: Record<string, React.ReactNode> = {
  'ip-triage':            <IconCrosshair />,
  'domain-triage':        <IconGlobe />,
  'url-phishing':         <IconLink />,
  'spam-source':          <IconMail />,
  'malware-hash':         <IconHash />,
  'suspicious-connection':<IconShare />,
  'waf-web-attack':       <IconShield />,
  'dark-web-exposure':    <IconEye />,
  'takedown-reporting':   <IconFlag />,
  'ransomware-context':   <IconLock />,
  'external-exposure':    <IconRadio />,
  'email-header-review':  <IconMailOpen />,
  'cve-context':             <IconCve />,
  'business-domain-osint':   <IconBuilding />,
};

const DEFAULT_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

// ── Analysis bar: run control + workflows applicable to the current IOC ──────

interface AnalysisBarProps {
  ioc: DetectedIoc | null;
  workflows: Workflow[];
  selectedWorkflow: Workflow | null;
  onSelectWorkflow: (workflow: Workflow) => void;
  onRunAnalysis: () => void;
  onForceRunAnalysis: () => void;
  analysisLoading: boolean;
  hasAnalysisResult: boolean;
  backendOnline: boolean | null;
}

export function AnalysisBar({
  ioc,
  workflows,
  selectedWorkflow,
  onSelectWorkflow,
  onRunAnalysis,
  onForceRunAnalysis,
  analysisLoading,
  hasAnalysisResult,
  backendOnline,
}: AnalysisBarProps) {
  const disabled = !ioc || !ioc.trimmed || (ioc.type === 'unknown' && !ioc.isEmailHeader);
  const hasIoc = !disabled;
  const offline = backendOnline === false;

  const applicableWorkflows = hasIoc
    ? workflows.filter(w => isWorkflowEnabled(w, ioc).enabled)
    : [];

  return (
    <div className="wb-card">
      <div className="flex flex-col md:flex-row md:items-center gap-3 px-4 py-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 mb-1.5">
            <p className="wb-label">Workflow</p>
            <p className="text-[11px] text-fg-4 truncate">
              {!hasIoc
                ? 'Shows playbooks that apply once an indicator is entered'
                : selectedWorkflow
                  ? selectedWorkflow.description
                  : 'Optional — scopes providers, pivot tools and checklist'}
            </p>
          </div>
          {!hasIoc ? (
            <div className="h-7 flex items-center text-xs text-fg-4">—</div>
          ) : applicableWorkflows.length === 0 ? (
            <div className="h-7 flex items-center text-xs text-fg-4">No workflows apply to this indicator type.</div>
          ) : (
            <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Investigation workflow">
              {applicableWorkflows.map(workflow => {
                const isSelected = selectedWorkflow?.id === workflow.id;
                const icon = WORKFLOW_ICONS[workflow.id] ?? DEFAULT_ICON;
                return (
                  <button
                    key={workflow.id}
                    role="radio"
                    aria-checked={isSelected}
                    onClick={() => onSelectWorkflow(workflow)}
                    title={workflow.description}
                    className={`flex items-center gap-1.5 h-7 px-2.5 rounded-md border text-xs whitespace-nowrap transition-colors ${
                      isSelected
                        ? 'bg-accent-bg border-accent-line text-accent-fg font-medium'
                        : 'bg-surface border-line text-fg-2 hover:border-line-strong hover:text-fg-1'
                    }`}
                  >
                    <span className="w-3.5 h-3.5 shrink-0 block">{icon}</span>
                    {workflow.name}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0 md:pl-4 md:border-l md:border-line md:self-stretch">
          {hasAnalysisResult && !analysisLoading && (
            <button
              onClick={onForceRunAnalysis}
              title="Ignore cached provider results"
              className="h-8 px-3 text-xs font-medium rounded-md border border-line bg-surface text-fg-2 hover:border-line-strong hover:text-fg-1 transition-colors"
            >
              Bypass cache
            </button>
          )}
          <button
            onClick={onRunAnalysis}
            disabled={disabled || analysisLoading || offline}
            title={offline ? 'Backend offline — run npm run backend:dev' : 'Enrich across providers and summarise (⌘↵)'}
            className="inline-flex items-center gap-2 h-8 px-3.5 text-xs font-semibold rounded-md bg-accent text-white hover:bg-accent-strong transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {analysisLoading ? (
              <>
                <span className="w-3 h-3 rounded-full border-[1.5px] border-white/30 border-t-white animate-spin" />
                Analysing…
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  {hasAnalysisResult ? <path d="M3 12a9 9 0 0115.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 01-15.5 6.2L3 16M3 21v-5h5" /> : <path d="M5 12h14M13 6l6 6-6 6" />}
                </svg>
                {hasAnalysisResult ? 'Re-analyse' : 'Run analysis'}
              </>
            )}
          </button>
        </div>
      </div>
      {offline && hasIoc && (
        <div className="px-4 py-2 border-t border-line text-xs text-warn-fg bg-warn-bg rounded-b-xl">
          The enrichment backend isn’t reachable. Start it with <code className="font-mono">npm run backend:dev</code> — pivot tools below still work.
        </div>
      )}
    </div>
  );
}
