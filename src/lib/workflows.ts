import type { DetectedIoc, IocType } from '../types/ioc';
import type { Workflow } from '../types/workflow';

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
