import type { Tool } from '../types/tool';
import type { DetectedIoc } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import { ToolCard } from './ToolCard';
import { CopyButton } from './CopyButton';
import { applyTemplate, buildTemplateVars } from '../lib/template';

interface ToolPanelProps {
  workflow: Workflow | null;
  ioc: DetectedIoc | null;
  tools: Tool[];
  favorites: Set<string>;
  onToggleFavorite: (toolId: string) => void;
}

export function ToolPanel({ workflow, ioc, tools, favorites, onToggleFavorite }: ToolPanelProps) {
  const isEmailHeaderWorkflow = workflow?.id === 'email-header-review';
  const isEmpty = !workflow || !ioc || (ioc.type === 'unknown' && !ioc.isEmailHeader && !isEmailHeaderWorkflow);

  if (isEmpty) {
    return (
      <div className="wb-card">
        <div className="px-4 py-3 border-b border-line">
          <p className="wb-label">Pivot tools</p>
        </div>
        <p className="px-4 py-6 text-xs text-fg-4">
          {!ioc ? 'Enter an indicator, then choose a workflow to get pre-filled links to external tools.'
            : !workflow ? 'Choose a workflow above to list the pivot tools for this indicator.'
            : 'This indicator type isn’t supported by the selected workflow.'}
        </p>
      </div>
    );
  }

  const workflowTools = workflow.toolIds
    .map(id => tools.find(t => t.id === id))
    .filter((t): t is Tool => t !== undefined);

  if (workflowTools.length === 0) {
    return (
      <div className="wb-card">
        <div className="px-4 py-3 border-b border-line"><p className="wb-label">Pivot tools</p></div>
        <p className="px-4 py-6 text-xs text-fg-4">No tools are configured for this workflow.</p>
      </div>
    );
  }

  const vars = buildTemplateVars(ioc);
  const allLinks = workflowTools.map(t => {
    const url = applyTemplate(t.urlTemplate, vars);
    const hasUnfilled = /\{\{[^}]+\}\}/.test(url);
    return hasUnfilled ? `${t.name}: ${t.urlTemplate}` : `${t.name}: ${url}`;
  }).join('\n');

  const isSensitiveUrl = ioc.isSensitiveUrl ?? false;
  const favTools   = workflowTools.filter(t => favorites.has(t.id));
  const otherTools = workflowTools.filter(t => !favorites.has(t.id));

  const publicCount = workflowTools.filter(t => t.submissionRisk !== 'low').length;

  const renderRows = (list: Tool[], fav: boolean) => list.map(tool => (
    <ToolCard
      key={tool.id}
      tool={tool}
      ioc={ioc}
      isSensitiveUrl={isSensitiveUrl}
      isFavorite={fav}
      onToggleFavorite={onToggleFavorite}
    />
  ));

  return (
    <div className="wb-card overflow-hidden">
      <div className="flex items-center justify-between gap-4 px-4 py-3 border-b border-line">
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <p className="wb-label">Pivot tools</p>
            <span className="text-[11px] text-fg-4 tabular-nums">{workflowTools.length}</span>
          </div>
          <p className="text-[11px] text-fg-4 mt-0.5 truncate">
            {workflow.name}
            {publicCount > 0 && <> · <span className="text-warn-fg">{publicCount} share the indicator with a third party</span></>}
          </p>
        </div>
        <CopyButton text={allLinks} label="all links" />
      </div>

      <div className="hidden md:grid grid-cols-[minmax(0,1fr)_96px_96px_auto] gap-x-4 px-4 py-1.5 border-b border-line-soft bg-inset text-[11px] text-fg-4">
        <span className="pl-5">Tool</span>
        <span>Exposure</span>
        <span>Access</span>
        <span className="w-[108px]" />
      </div>

      <div className="divide-y divide-line-soft">
        {favTools.length > 0 && (
          <>
            <p className="px-4 py-1.5 text-[11px] font-medium text-fg-4 bg-inset">Pinned</p>
            {renderRows(favTools, true)}
            {otherTools.length > 0 && <p className="px-4 py-1.5 text-[11px] font-medium text-fg-4 bg-inset">All tools</p>}
          </>
        )}
        {renderRows(otherTools, false)}
      </div>
    </div>
  );
}
