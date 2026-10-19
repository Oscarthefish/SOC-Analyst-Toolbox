import type { EnrichmentResult } from '../types/enrichment';
import { TECHNIQUE_BY_ID, TACTIC_BY_ID } from '../data/attack';
import { hasData } from './severityMix';

/**
 * Which ATT&CK techniques an investigation points at, and why. Every technique
 * carries its evidence so the analyst can judge it:
 *  - reported: a provider lists the technique id against this indicator
 *  - inferred: a provider label (tag, threat type) maps to the technique
 *  - context:  the chosen workflow is about this kind of activity
 */

export type EvidenceKind = 'reported' | 'inferred' | 'context';

export interface Evidence {
  kind: EvidenceKind;
  /** Provider or workflow name */
  source: string;
  /** e.g. the label that matched */
  detail?: string;
}

export interface TechniqueHit {
  id: string;
  name: string;
  /** Primary tactic id, or '' when the technique isn't in the local catalogue */
  tactic: string;
  evidence: Evidence[];
}

export const EVIDENCE_RANK: Record<EvidenceKind, number> = { reported: 0, inferred: 1, context: 2 };

/** Provider labels → techniques. Patterns are matched against lower-cased tags and threat types. */
const LABEL_RULES: [RegExp, string[]][] = [
  [/password spray/, ['T1110.003']],
  [/credential stuff/, ['T1110.004']],
  [/ssh.*brute|brute.*ssh/, ['T1110', 'T1021.004']],
  [/rdp.*brute|brute.*rdp/, ['T1110', 'T1021.001']],
  [/brute ?forc/, ['T1110']],
  [/vuln(erability)? ?scan|nuclei|exploit/, ['T1595.002', 'T1190']],
  [/scanner|scanning|masscan|zmap|port ?scan/, ['T1595']],
  [/\btor\b|tor exit|onion/, ['T1090.003']],
  [/\bproxy\b|\bvpn\b|anonymi[sz]/, ['T1090']],
  [/social_engineering|phish/, ['T1566.002']],
  [/botnet_cc|\bc2\b|c&c|command.and.control|cobalt ?strike|sliver|beacon/, ['T1071']],
  [/payload_delivery|malware_download|dropper|loader/, ['T1105']],
  [/ransom/, ['T1486']],
  [/stealer/, ['T1555']],
  [/miner|mining|xmrig|cryptojack/, ['T1496']],
  [/\bdga\b/, ['T1568.002']],
  [/web ?shell/, ['T1505.003']],
  [/dns.?tunnel/, ['T1071.004', 'T1572']],
];

/** Workflow → techniques the investigation is typically about. */
export const WORKFLOW_TECHNIQUES: Record<string, string[]> = {
  'suspicious-connection': ['T1071', 'T1571', 'T1573', 'T1041'],
  'waf-web-attack': ['T1190', 'T1595.002', 'T1505.003'],
  'url-phishing': ['T1566.002', 'T1204.001', 'T1539'],
  'spam-source': ['T1566', 'T1566.001', 'T1566.002'],
  'email-header-review': ['T1566', 'T1566.001', 'T1566.002'],
  'malware-hash': ['T1204.002', 'T1105', 'T1059'],
  'dark-web-exposure': ['T1078', 'T1110.004', 'T1555'],
  'ransomware-context': ['T1486', 'T1490', 'T1567'],
  'external-exposure': ['T1133', 'T1190', 'T1595'],
  'cve-context': ['T1190', 'T1068'],
  'domain-triage': ['T1583.001', 'T1568'],
  'takedown-reporting': ['T1583.001'],
};

const LABEL_FACTS = new Set(['Tags', 'Threat types', 'Threat type', 'Threat category', 'Threat', 'Threats']);

export function deriveTechniques(results: EnrichmentResult[], workflow?: { id: string; name: string } | null): TechniqueHit[] {
  const hits = new Map<string, TechniqueHit>();

  function add(id: string, ev: Evidence, providerName?: string) {
    const known = TECHNIQUE_BY_ID.get(id);
    let hit = hits.get(id);
    if (!hit) {
      hit = { id, name: known?.name ?? providerName ?? id, tactic: known?.tactics[0] ?? '', evidence: [] };
      hits.set(id, hit);
    }
    if (!hit.evidence.some(e => e.kind === ev.kind && e.source === ev.source && e.detail === ev.detail)) hit.evidence.push(ev);
  }

  for (const r of results.filter(hasData)) {
    for (const ref of r.attackTechniques ?? []) add(ref.id, { kind: 'reported', source: r.providerName }, ref.name);

    const labels = (r.keyFacts ?? [])
      .filter(f => LABEL_FACTS.has(f.label))
      .flatMap(f => f.value.split(','))
      .map(v => v.trim())
      .filter(Boolean);
    for (const label of labels) {
      const lower = label.toLowerCase();
      for (const [re, ids] of LABEL_RULES) {
        if (!re.test(lower)) continue;
        for (const id of ids) add(id, { kind: 'inferred', source: r.providerName, detail: label });
        break; // first (most specific) rule wins for a label
      }
    }
  }

  if (workflow) {
    for (const id of WORKFLOW_TECHNIQUES[workflow.id] ?? []) add(id, { kind: 'context', source: workflow.name });
  }

  const best = (h: TechniqueHit) => Math.min(...h.evidence.map(e => EVIDENCE_RANK[e.kind]));
  const tacticOrder = (h: TechniqueHit) => {
    const idx = [...TACTIC_BY_ID.keys()].indexOf(h.tactic);
    return idx === -1 ? 99 : idx;
  };
  return [...hits.values()].sort((a, b) => best(a) - best(b) || tacticOrder(a) - tacticOrder(b) || a.id.localeCompare(b.id));
}
