import type { DetectedIoc } from '../types/ioc';
import type { Workflow } from '../types/workflow';
import type { Tool } from '../types/tool';
import type { AssessmentState } from '../types/case';
import type { EnrichmentResponse } from '../types/enrichment';
import { applyTemplate, buildTemplateVars } from './template';

const ALL_PROVIDER_IDS = [
  'greynoise',
  'abuseipdb',
  'virustotal',
  'urlscan',
  'shodan',
  'censys',
  'ipinfo',
];

const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  greynoise: 'GreyNoise',
  abuseipdb: 'AbuseIPDB',
  virustotal: 'VirusTotal',
  urlscan: 'urlscan.io',
  shodan: 'Shodan',
  censys: 'Censys',
  ipinfo: 'IPinfo',
};

export function generateCaseNote(
  ioc: DetectedIoc,
  workflow: Workflow,
  tools: Tool[],
  checkedItems: Set<string>,
  assessmentState?: AssessmentState,
  enrichment?: EnrichmentResponse,
): string {
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const vars = buildTemplateVars(ioc);

  const toolsSection = tools
    .map(t => {
      const link = applyTemplate(t.urlTemplate, vars);
      return `### ${t.name}\n- Link: ${link}\n- Finding: _[analyst to complete]_`;
    })
    .join('\n\n');

  const internalSection = workflow.internalSearches
    .map(s => `- ${s.label}: \`${applyTemplate(s.template, vars)}\``)
    .join('\n');

  const checklistSection = workflow.checklist
    .map(item => {
      const checked = checkedItems.has(item);
      return `- [${checked ? 'x' : ' '}] ${item}`;
    })
    .join('\n');

  const verdictLabel = assessmentState?.verdict
    ? assessmentState.verdict.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    : '_[analyst to complete]_';

  const confidenceLabel = assessmentState?.confidence
    ? assessmentState.confidence.charAt(0).toUpperCase() + assessmentState.confidence.slice(1)
    : '_[analyst to complete]_';

  const actionsSection = assessmentState?.actionsTaken?.length
    ? assessmentState.actionsTaken.map(a => `- ${a}`).join('\n')
    : '- _[analyst to complete]_';

  const privacyNote = ioc.isSensitiveUrl
    ? '\n> **Privacy warning:** This URL may contain sensitive tokens or identifiers. Do not submit to public tools.\n'
    : '';

  let apiEnrichmentSection = '';
  if (enrichment) {
    const overall = enrichment.overall;
    const checkedAtDate = enrichment.results[0]?.checkedAt
      ? new Date(enrichment.results[0].checkedAt).toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
      : now;

    const providerLines = ALL_PROVIDER_IDS.map(pid => {
      const result = enrichment.results.find(r => r.providerId === pid);
      const displayName = PROVIDER_DISPLAY_NAMES[pid] ?? pid;
      if (!result) return `- ${displayName}: not run`;
      if (result.status === 'missing_key') return `- ${displayName}: API key not configured`;
      if (result.status === 'unsupported_ioc') return `- ${displayName}: IOC type not supported`;
      if (result.status === 'error') return `- ${displayName}: error — ${result.errorMessage ?? 'unknown'}`;
      if (result.status === 'rate_limited') return `- ${displayName}: rate limited`;
      if (result.status === 'skipped_safety') return `- ${displayName}: skipped (sensitive URL)`;
      return `- ${displayName}: [${result.severity.toUpperCase()}] ${result.summary}`;
    }).join('\n');

    apiEnrichmentSection = `
---

## API Enrichment Summary

- **Overall Severity:** ${overall.severity.charAt(0).toUpperCase() + overall.severity.slice(1)}
- **Overall Confidence:** ${overall.confidence.charAt(0).toUpperCase() + overall.confidence.slice(1)}
- **Summary:** ${overall.summary}
- **Recommended Actions:**
${overall.recommendedActions.map(a => `  - ${a}`).join('\n')}

### Provider Results

${providerLines}

Checked at: ${checkedAtDate}`;
  }

  return `# SOC Investigation Note

**Date/Time:** ${now}
**Analyst:** [analyst name]
**Case/Ticket:** [ticket reference]
${privacyNote}
---

## IOC
- **Original:** \`${ioc.original}\`
- **Normalised:** \`${ioc.normalised}\`
- **Type:** ${ioc.type.toUpperCase()}
- **Workflow:** ${workflow.name}
- **Expected Outcome:** ${workflow.expectedOutcome}

---

## External Enrichment

${toolsSection || '_No tools selected_'}

---

## Internal Telemetry To Check

${internalSection || '_No internal searches defined_'}

---

## Checklist

${checklistSection || '_No checklist defined_'}

---

## Assessment

**Verdict:** ${verdictLabel}
**Confidence:** ${confidenceLabel}
**Reasoning:** _[analyst to complete]_

---

## Recommended Actions

${actionsSection}
${apiEnrichmentSection}
`;
}
