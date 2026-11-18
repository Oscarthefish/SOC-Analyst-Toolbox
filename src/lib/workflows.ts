import type { DetectedIoc, IocType } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import type { Tool } from '../types/tool';

export const EMAIL_HEADER_WORKFLOW_ID = 'email-header-review';

/**
 * Whether a workflow applies to the current input. Email Header Review is for raw
 * pasted headers only; other workflows go by indicator type, with URLs also
 * accepted by domain workflows (via their hostname).
 */
export function isWorkflowEnabled(workflow: Workflow, ioc: DetectedIoc | null): { enabled: boolean; reason?: string } {
  if (workflow.id === EMAIL_HEADER_WORKFLOW_ID) {
    return ioc?.isEmailHeader ? { enabled: true } : { enabled: false, reason: 'Paste raw email headers to enable' };
  }
  if (!ioc || ioc.type === 'unknown') {
    return { enabled: false, reason: 'Enter an IOC to enable' };
  }
  const effectiveType: IocType =
    ioc.type === 'url' && workflow.allowedInputTypes.includes('domain') ? 'domain' : ioc.type;
  if (workflow.allowedInputTypes.includes(effectiveType)) return { enabled: true };
  return { enabled: false, reason: `Needs ${workflow.allowedInputTypes.map(t => t.toUpperCase()).join(', ')}` };
}

/**
 * The pivot tools a workflow lists for an indicator: the workflow's own tools in their
 * set order, then any custom tool assigned to the workflow that accepts this indicator type.
 */
export function toolsForWorkflow(workflow: Workflow, tools: Tool[], ioc: DetectedIoc): Tool[] {
  const own = workflow.toolIds
    .map(id => tools.find(t => t.id === id))
    .filter((t): t is Tool => t !== undefined);
  const listed = new Set(workflow.toolIds);
  const assigned = tools.filter(t =>
    !listed.has(t.id) && t.workflows.includes(workflow.id) && (ioc.isEmailHeader || t.inputTypes.includes(ioc.type)));
  return [...own, ...assigned];
}
