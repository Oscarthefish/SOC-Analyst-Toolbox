import { useState } from 'react';
import type { Tool } from '../types/tool';
import type { DetectedIoc } from '../types/ioc';
import { applyTemplate, buildTemplateVars, safeHref } from '../lib/template';
import { CopyButton } from './CopyButton';

interface ToolCardProps {
  tool: Tool;
  ioc: DetectedIoc;
  isSensitiveUrl: boolean;
  isFavorite?: boolean;
  onToggleFavorite?: (toolId: string) => void;
}

const RISK: Record<string, { label: string; title: string; cls: string; dot: string }> = {
  low:    { label: 'Passive',     title: 'Lookup only — the indicator is not shared or stored publicly.', cls: 'text-ok-fg',     dot: 'bg-ok' },
  medium: { label: 'Submits IOC', title: 'The indicator is sent to the service and may be logged or visible to its users.', cls: 'text-warn-fg',   dot: 'bg-warn' },
  high:   { label: 'Public',      title: 'Submitting makes the indicator public (e.g. live scans, shared sandboxes).', cls: 'text-danger-fg', dot: 'bg-danger' },
};

const ACCESS: Record<string, string> = {
  none: 'Free',
  free_account: 'Free account',
  trial: 'Trial',
  paid: 'Paid',
  mixed: 'Free / paid',
};

export function RiskBadge({ risk }: { risk: string }) {
  const r = RISK[risk] ?? RISK['high']!;
  return (
    <span title={r.title} className={`inline-flex items-center gap-1.5 text-[11px] font-medium whitespace-nowrap ${r.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${r.dot}`} />
      {r.label}
    </span>
  );
}

function StarIcon({ filled }: { filled: boolean }) {
  return (
    <svg className="w-3.5 h-3.5" fill={filled ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
    </svg>
  );
}

export function ToolCard({ tool, ioc, isSensitiveUrl, isFavorite = false, onToggleFavorite }: ToolCardProps) {
  const vars = buildTemplateVars(ioc);
  const generatedUrl = applyTemplate(tool.urlTemplate, vars);
  const canGenerate = !/\{\{[^}]+\}\}/.test(generatedUrl);
  const href = safeHref(canGenerate ? generatedUrl : tool.urlTemplate);
  const [expanded, setExpanded] = useState(false);
  const blockedBySensitivity = isSensitiveUrl && tool.submissionRisk !== 'low';

  return (
    <div className={`group ${expanded ? 'bg-inset' : 'hover:bg-inset'} transition-colors`}>
      <div className="grid grid-cols-[1fr_auto] md:grid-cols-[minmax(0,1fr)_96px_96px_auto] items-center gap-x-4 px-4 py-2.5">
        <button
          onClick={() => setExpanded(e => !e)}
          aria-expanded={expanded}
          className="min-w-0 text-left flex items-start gap-2"
        >
          <svg className={`w-3 h-3 mt-1 shrink-0 text-fg-4 transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          <span className="min-w-0">
            <span className="flex items-center gap-2">
              <span className="text-[13px] font-medium text-fg-1 truncate">{tool.name}</span>
              {!canGenerate && <span className="text-[10px] text-fg-4 border border-line rounded px-1">manual</span>}
            </span>
            <span className="block text-xs text-fg-3 truncate">{tool.description}</span>
          </span>
        </button>

        <div className="hidden md:block"><RiskBadge risk={tool.submissionRisk} /></div>
        <div className="hidden md:block text-[11px] text-fg-3 whitespace-nowrap">{ACCESS[tool.requiresAccount] ?? tool.requiresAccount}</div>

        <div className="flex items-center gap-1">
          {onToggleFavorite && (
            <button
              onClick={() => onToggleFavorite(tool.id)}
              title={isFavorite ? 'Remove from pinned' : 'Pin to top'}
              aria-pressed={isFavorite}
              className={`w-7 h-7 rounded-md flex items-center justify-center transition-colors ${
                isFavorite ? 'text-warn' : 'text-fg-4 opacity-0 group-hover:opacity-100 focus:opacity-100 hover:text-fg-2'
              }`}
            >
              <StarIcon filled={isFavorite} />
            </button>
          )}
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            aria-disabled={href === undefined}
            title={href === undefined ? 'Invalid tool URL — only http(s) links are allowed' : blockedBySensitivity ? 'Sensitive URL — this tool shares indicators externally' : `Open in ${tool.name}`}
            className={`inline-flex items-center gap-1 h-7 px-2.5 rounded-md border text-xs font-medium transition-colors ${
              href === undefined
                ? 'border-line text-fg-4 cursor-not-allowed'
                : blockedBySensitivity
                ? 'border-warn-line text-warn-fg bg-warn-bg'
                : 'border-line bg-surface text-fg-2 hover:border-accent hover:text-accent-fg'
            }`}
          >
            Open
            <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.8} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M9 7h8v8" />
            </svg>
          </a>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-3 pl-9 grid md:grid-cols-3 gap-x-6 gap-y-2 text-xs">
          <div className="md:hidden flex items-center gap-3 col-span-full">
            <RiskBadge risk={tool.submissionRisk} />
            <span className="text-[11px] text-fg-3">{ACCESS[tool.requiresAccount] ?? tool.requiresAccount}</span>
          </div>
          <div>
            <p className="text-fg-4 mb-0.5">Why use it</p>
            <p className="text-fg-2 leading-relaxed">{tool.whyUse}</p>
          </div>
          <div>
            <p className="text-fg-4 mb-0.5">What to look for</p>
            <p className="text-fg-2 leading-relaxed">{tool.lookFor}</p>
          </div>
          <div>
            <p className="text-fg-4 mb-0.5">Exposure</p>
            <p className="text-fg-2 leading-relaxed">{tool.riskNote}</p>
          </div>
          {canGenerate && (
            <div className="col-span-full flex items-center gap-2 pt-1">
              <code className="flex-1 min-w-0 text-[11px] font-mono text-fg-3 truncate">{generatedUrl}</code>
              <CopyButton text={generatedUrl} label="link" iconOnly />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
