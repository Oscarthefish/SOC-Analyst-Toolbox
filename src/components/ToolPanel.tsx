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
  const isEmpty = !workflow || !ioc || (ioc.type === 'unknown' && !ioc.isEmailHeader);

  if (isEmpty) {
    return (
      <div className="wb-card p-5">
        <p className="wb-label mb-4">Recommended Tools</p>
        <div className="flex items-center justify-center py-10">
          <div className="text-center space-y-2">
            <div className="w-10 h-10 rounded-xl bg-[#f2f4f7] flex items-center justify-center mx-auto">
              <svg className="w-5 h-5 text-[#98a2b3]" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
              </svg>
            </div>
            <p className="text-sm text-[#667085]">
              {!ioc ? 'Enter an IOC to see tools.' : !workflow ? 'Select a workflow to see tools.' : 'Unsupported IOC type.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  const workflowTools = workflow.toolIds
    .map(id => tools.find(t => t.id === id))
    .filter((t): t is Tool => t !== undefined);

  if (workflowTools.length === 0) {
    return (
      <div className="wb-card p-5">
        <p className="wb-label mb-4">Recommended Tools</p>
        <p className="text-sm text-[#667085]">No tools configured for this workflow.</p>
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

  return (
    <div className="wb-card p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="wb-label">Recommended Tools</p>
          <p className="text-xs text-[#98a2b3] mt-0.5">
            {workflowTools.length} tools · {workflow.name}
          </p>
        </div>
        <CopyButton text={allLinks} label="all links" />
      </div>

      <div className="space-y-1.5">
        {favTools.length > 0 && (
          <>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#b54708] flex items-center gap-1.5 mb-2">
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
              Favourites
            </p>
            {favTools.map(tool => (
              <ToolCard
                key={tool.id}
                tool={tool}
                ioc={ioc}
                isSensitiveUrl={isSensitiveUrl}
                isFavorite={true}
                onToggleFavorite={onToggleFavorite}
              />
            ))}
            {otherTools.length > 0 && (
              <div className="border-t border-[#f2f4f7] pt-3 mt-3">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[#98a2b3] mb-2">All Tools</p>
              </div>
            )}
          </>
        )}
        {otherTools.map(tool => (
          <ToolCard
            key={tool.id}
            tool={tool}
            ioc={ioc}
            isSensitiveUrl={isSensitiveUrl}
            isFavorite={false}
            onToggleFavorite={onToggleFavorite}
          />
        ))}
      </div>
    </div>
  );
}
