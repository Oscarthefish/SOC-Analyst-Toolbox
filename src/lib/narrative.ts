import type { EnrichmentResult } from '../types/enrichment';

/** Sections of the local LLM's analyst narrative (see buildAnalysisPrompt in the backend). */
export interface ParsedNarrative {
  verdict: string | null;
  findings: string[];
  actions: string[];
  notes: string | null;
}

function parseBullets(block: string): string[] {
  return block
    .split('\n')
    .map(l => l.replace(/^\s*[-•*]\s+/, '').replace(/^\d+\.\s+/, '').trim())
    .filter(Boolean);
}

export function parseNarrative(text: string): ParsedNarrative {
  const t = text.trim();
  const verdictMatch = t.match(/VERDICT:\s*(.+)/i);
  const verdict = verdictMatch ? verdictMatch[1]!.replace(/\*+/g, '').trim() : null;

  function extractSection(name: string): string {
    const re = new RegExp(`${name}:\\s*\\n([\\s\\S]*?)(?=\\n[A-Z ]{3,}:|$)`, 'i');
    const m = t.match(re);
    return m ? m[1]!.trim() : '';
  }

  const findings = parseBullets(extractSection('KEY FINDINGS'));
  const actions = parseBullets(extractSection('RECOMMENDED ACTIONS'));
  const notes = extractSection('ANALYST NOTES').replace(/^[-•*]\s+/gm, '').trim() || null;

  return { verdict, findings, actions, notes };
}

/** Map provider names and ids (lowercased) to their source URLs. */
export function buildSourceMap(results: EnrichmentResult[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const r of results) {
    if (!r.sourceUrl) continue;
    map.set(r.providerName.toLowerCase(), r.sourceUrl);
    map.set(r.providerId.toLowerCase(), r.sourceUrl);
  }
  return map;
}

/** Source URL for the first provider a finding mentions, if any. */
export function findSourceUrl(finding: string, sourceMap: Map<string, string>): string | null {
  const lower = finding.toLowerCase();
  for (const [key, url] of sourceMap) {
    if (lower.includes(key)) return url;
  }
  return null;
}
