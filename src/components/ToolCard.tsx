import { useState } from 'react';
import type { Tool } from '../types/tool';
import type { DetectedIoc } from '../types/ioc';
import { applyTemplate, buildTemplateVars } from '../lib/template';
import { CopyButton } from './CopyButton';

interface ToolCardProps {
  tool: Tool;
  ioc: DetectedIoc;
  isSensitiveUrl: boolean;
  isFavorite?: boolean;
  onToggleFavorite?: (toolId: string) => void;
}

function RiskBadge({ risk }: { risk: string }) {
  if (risk === 'low') return (
    <span className="inline-flex items-center gap-1 h-5 px-2 rounded-md text-[11px] font-semibold bg-[#ecfdf3] border border-[#abefc6] text-[#067647]">
      <span className="w-1.5 h-1.5 rounded-full bg-[#079455]" />
      Passive
    </span>
  );
  if (risk === 'medium') return (
    <span className="inline-flex items-center gap-1 h-5 px-2 rounded-md text-[11px] font-semibold bg-[#fffaeb] border border-[#fedf89] text-[#b54708]">
      Submits IOC
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 h-5 px-2 rounded-md text-[11px] font-semibold bg-[#fef3f2] border border-[#fecdca] text-[#b42318]">
      Submits IOC
    </span>
  );
}

function AccessBadge({ requires }: { requires: string }) {
  if (requires === 'none') return (
    <span className="text-[11px] text-[#667085]">Free</span>
  );
  if (requires === 'free_account') return (
    <span className="text-[11px] text-[#667085]">Free account</span>
  );
  if (requires === 'paid') return (
    <span className="text-[11px] text-[#667085]">Paid</span>
  );
  return <span className="text-[11px] text-[#667085]">{requires}</span>;
}

// Monogram initials tile
function Initials({ name }: { name: string }) {
  const parts = name.split(/[\s-_/]+/).filter(Boolean);
  const letters = parts.length >= 2
    ? (parts[0]![0]! + parts[1]![0]!).toUpperCase()
    : name.slice(0, 2).toUpperCase();
  return (
    <div className="w-9 h-9 rounded-[9px] bg-[#f2f4f7] border border-[#e4e7ec] flex items-center justify-center shrink-0">
      <span className="text-[11px] font-bold font-mono text-[#475467] tracking-wide">{letters}</span>
    </div>
  );
}

export function ToolCard({ tool, ioc, isSensitiveUrl, isFavorite = false, onToggleFavorite }: ToolCardProps) {
  const vars = buildTemplateVars(ioc);
  const generatedUrl = applyTemplate(tool.urlTemplate, vars);
  const hasUnfilledVars = /\{\{[^}]+\}\}/.test(generatedUrl);
  const canGenerate = !hasUnfilledVars;
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`group flex items-start gap-3 p-3 rounded-[10px] border transition-colors ${
      expanded
        ? 'bg-[#f9fafb] border-[#d0d5dd]'
        : 'bg-white border-[#e4e7ec] hover:border-[#d0d5dd] hover:bg-[#f9fafb]'
    }`}>
      <Initials name={tool.name} />

      <div className="flex-1 min-w-0 space-y-1.5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold text-[#101828] leading-tight truncate">{tool.name}</p>
            <p className="text-xs text-[#667085] leading-snug mt-0.5 line-clamp-2">{tool.description}</p>
          </div>
          <a
            href={canGenerate ? generatedUrl : tool.urlTemplate}
            target="_blank"
            rel="noopener noreferrer"
            title={`Open ${tool.name}`}
            className="shrink-0 w-7 h-7 rounded-lg border border-[#e4e7ec] bg-white flex items-center justify-center text-[#667085] hover:border-[#1570ef] hover:text-[#1570ef] transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6m4-3h6v6m-11 5L21 3" />
            </svg>
          </a>
        </div>

        {/* Badges row */}
        <div className="flex flex-wrap items-center gap-1.5">
          <RiskBadge risk={tool.submissionRisk} />
          <AccessBadge requires={tool.requiresAccount} />
          {isSensitiveUrl && (
            <span className="text-[11px] text-[#b54708] font-medium">· Sensitive URL</span>
          )}
        </div>

        {/* Favourite toggle */}
        {onToggleFavorite && (
          <button
            onClick={() => onToggleFavorite(tool.id)}
            className={`text-[11px] flex items-center gap-1 transition-colors ${
              isFavorite ? 'text-[#b54708]' : 'text-[#98a2b3] hover:text-[#667085]'
            }`}
          >
            <svg className="w-3 h-3" fill={isFavorite ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
            </svg>
            {isFavorite ? 'Favourited' : 'Favourite'}
          </button>
        )}

        {/* Expandable detail */}
        {expanded && (
          <div className="pt-2 border-t border-[#f2f4f7] space-y-2">
            <div>
              <p className="text-[11px] font-semibold text-[#98a2b3] uppercase tracking-wider mb-0.5">Why use it</p>
              <p className="text-xs text-[#475467]">{tool.whyUse}</p>
            </div>
            <div>
              <p className="text-[11px] font-semibold text-[#98a2b3] uppercase tracking-wider mb-0.5">What to look for</p>
              <p className="text-xs text-[#475467]">{tool.lookFor}</p>
            </div>
            <div>
              <p className="text-[11px] font-semibold text-[#98a2b3] uppercase tracking-wider mb-0.5">Risk note</p>
              <p className="text-xs text-[#667085] italic">{tool.riskNote}</p>
            </div>
            {canGenerate && (
              <div className="flex items-center gap-2">
                <code className="text-[11px] font-mono text-[#667085] break-all flex-1">{generatedUrl}</code>
                <CopyButton text={generatedUrl} label="link" iconOnly />
              </div>
            )}
          </div>
        )}

        <button
          onClick={() => setExpanded(e => !e)}
          className="text-[11px] text-[#98a2b3] hover:text-[#667085] transition-colors"
        >
          {expanded ? 'Show less' : 'Details'}
        </button>
      </div>
    </div>
  );
}
