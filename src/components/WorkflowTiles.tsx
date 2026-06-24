import type { DetectedIoc, IocType } from '../types/ioc';
import type { Workflow } from '../types/workflow';

function IconSpark() {
  return (
    <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6L12 2z" />
    </svg>
  );
}

interface WorkflowTilesProps {
  ioc: DetectedIoc | null;
  workflows: Workflow[];
  selectedWorkflow: Workflow | null;
  onSelect: (workflow: Workflow) => void;
}

function isWorkflowEnabled(workflow: Workflow, ioc: DetectedIoc | null): { enabled: boolean; reason?: string } {
  // Email header review accepts raw header text, not a single typed IOC
  if (workflow.id === 'email-header-review') {
    if (!ioc || !ioc.trimmed) return { enabled: false, reason: 'Paste email headers to enable' };
    return { enabled: true };
  }

  if (!ioc || ioc.type === 'unknown') {
    return { enabled: false, reason: 'Enter an IOC to enable' };
  }
  const type: IocType = ioc.type;
  const effectiveType: IocType =
    type === 'url' && workflow.allowedInputTypes.includes('domain') ? 'domain' : type;
  if (workflow.allowedInputTypes.includes(effectiveType)) return { enabled: true };
  const allowed = workflow.allowedInputTypes.map(t => t.toUpperCase()).join(', ');
  return { enabled: false, reason: `Needs ${allowed}` };
}

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

export function WorkflowTiles({ ioc, workflows, selectedWorkflow, onSelect }: WorkflowTilesProps) {
  const isUsableIoc = ioc && (ioc.type !== 'unknown' || ioc.isEmailHeader);
  const enabledCount = isUsableIoc
    ? workflows.filter(w => isWorkflowEnabled(w, ioc).enabled).length
    : 0;

  return (
    <div className="wb-card p-5">
      <div className="flex items-center justify-between mb-4">
        <p className="wb-label">Investigation Workflow</p>
        {isUsableIoc && (
          <span className="text-xs text-[#667085]">
            {enabledCount} of {workflows.length} apply to {ioc.isEmailHeader ? 'EMAIL HEADER' : ioc.type.toUpperCase()}
          </span>
        )}
      </div>

      <div className="grid gap-2" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(212px, 1fr))' }}>
        {workflows.map(workflow => {
          const { enabled, reason } = isWorkflowEnabled(workflow, ioc);
          const isSelected = selectedWorkflow?.id === workflow.id;
          const icon = WORKFLOW_ICONS[workflow.id] ?? DEFAULT_ICON;

          return (
            <button
              key={workflow.id}
              disabled={!enabled}
              onClick={() => enabled && onSelect(workflow)}
              className={`
                group text-left p-3 rounded-[10px] border transition-all flex items-start gap-3
                ${isSelected
                  ? 'bg-[#eff8ff] border-[#1570ef] shadow-sm'
                  : enabled
                  ? 'bg-white border-[#e4e7ec] hover:border-[#b2ddff] hover:bg-[#f9fafb] cursor-pointer'
                  : 'bg-[#fafbfc] border-[#f2f4f7] cursor-not-allowed opacity-50'
                }
              `}
              title={!enabled ? reason : workflow.description}
            >
              {/* Icon tile */}
              <div className={`w-[34px] h-[34px] rounded-[9px] shrink-0 flex items-center justify-center ${
                isSelected ? 'bg-[#1570ef] text-white' : 'bg-[#f2f4f7] text-[#475467]'
              }`}>
                <span className="w-[18px] h-[18px] block">{icon}</span>
              </div>

              {/* Text */}
              <div className="min-w-0 flex-1 pt-0.5">
                <p className={`text-[13px] font-semibold leading-tight truncate ${
                  isSelected ? 'text-[#175cd3]' : 'text-[#101828]'
                }`}>
                  {workflow.name}
                </p>
                <p className={`text-xs mt-0.5 leading-tight ${
                  isSelected ? 'text-[#1570ef]' : !enabled ? 'text-[#98a2b3]' : 'text-[#667085]'
                }`}>
                  {isSelected ? 'Active workflow' : !enabled ? reason : workflow.description}
                </p>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Slim action bar: Auto Analysis trigger + horizontal workflow chips ────────

interface AnalysisBarProps {
  ioc: DetectedIoc | null;
  workflows: Workflow[];
  selectedWorkflow: Workflow | null;
  onSelectWorkflow: (workflow: Workflow) => void;
  onRunAnalysis: () => void;
  onForceRunAnalysis: () => void;
  analysisLoading: boolean;
  hasAnalysisResult: boolean;
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
}: AnalysisBarProps) {
  const disabled = !ioc || !ioc.trimmed || (ioc.type === 'unknown' && !ioc.isEmailHeader);
  const hasIoc = !disabled;

  // Only show workflows that apply to the current IOC — hides irrelevant options.
  const applicableWorkflows = hasIoc
    ? workflows.filter(w => isWorkflowEnabled(w, ioc).enabled)
    : [];

  return (
    <div className="wb-card flex items-stretch overflow-hidden">
      {/* Auto Analysis section */}
      <div className="flex items-center gap-3 px-4 py-3 shrink-0 border-r border-[#f2f4f7]">
        <div className={`w-8 h-8 rounded-[9px] flex items-center justify-center shrink-0 transition-colors ${
          hasAnalysisResult ? 'bg-[#eff8ff] text-[#1570ef]' : 'bg-[#f2f4f7] text-[#475467]'
        }`}>
          <IconSpark />
        </div>
        <div className="mr-1">
          <p className="text-[13px] font-semibold text-[#101828] leading-none">Auto Analysis</p>
          <p className="text-[11px] text-[#98a2b3] leading-none mt-0.5">AI-assisted verdict</p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {hasAnalysisResult && !analysisLoading && (
            <button
              onClick={onForceRunAnalysis}
              className="text-xs font-medium px-2.5 py-1.5 rounded-lg border border-[#e4e7ec] bg-white text-[#475467] hover:border-[#d0d5dd] transition-colors"
            >
              Re-run
            </button>
          )}
          <button
            onClick={onRunAnalysis}
            disabled={disabled || analysisLoading}
            className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-[#1570ef] text-white hover:bg-[#175cd3] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {analysisLoading ? (
              <>
                <div className="w-3 h-3 rounded-full border-[1.5px] border-white/30 border-t-white animate-spin" />
                Analysing…
              </>
            ) : (
              hasAnalysisResult ? '↺ Refresh' : '▶ Run'
            )}
          </button>
        </div>
      </div>

      {/* Workflow chips — wrapping, filtered to applicable only */}
      <div className="flex-1 min-w-0 px-3 py-3">
        {!hasIoc ? (
          <div className="flex items-center h-full">
            <p className="text-[12px] text-[#98a2b3]">Enter an IOC to see applicable investigation workflows.</p>
          </div>
        ) : applicableWorkflows.length === 0 ? (
          <div className="flex items-center h-full">
            <p className="text-[12px] text-[#98a2b3]">No investigation workflows apply to this IOC type.</p>
          </div>
        ) : (
          <>
            <p className="text-[10px] font-bold uppercase tracking-wider text-[#d0d5dd] mb-2 select-none">
              Investigation Workflow
            </p>
            <div className="flex flex-wrap gap-1.5">
              {applicableWorkflows.map(workflow => {
                const isSelected = selectedWorkflow?.id === workflow.id;
                const icon = WORKFLOW_ICONS[workflow.id] ?? DEFAULT_ICON;
                return (
                  <button
                    key={workflow.id}
                    onClick={() => onSelectWorkflow(workflow)}
                    title={workflow.description}
                    className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[12px] font-medium whitespace-nowrap transition-all ${
                      isSelected
                        ? 'bg-[#eff8ff] border-[#1570ef] text-[#175cd3]'
                        : 'bg-white border-[#e4e7ec] text-[#344054] hover:border-[#b2ddff] hover:bg-[#f9fafb]'
                    }`}
                  >
                    <span className="w-3.5 h-3.5 shrink-0 block">{icon}</span>
                    {workflow.name}
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
