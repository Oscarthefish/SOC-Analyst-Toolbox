import type { EnrichmentResult } from '../types/enrichment';
import { hasData } from './severityMix';

/**
 * What the providers say the indicator is connected to, merged across providers.
 * The same ASN reported by four sources becomes one node with four sources, so
 * corroboration is visible and disagreement (two different countries) stands out.
 */

export type RelationKind = 'network' | 'host' | 'registration' | 'exposure' | 'threat';

export const RELATION_LABEL: Record<RelationKind, string> = {
  network: 'Network',
  host: 'Related hosts',
  registration: 'Registration',
  exposure: 'Exposure',
  threat: 'Threat labels',
};

export interface RelationNode {
  id: string;
  kind: RelationKind;
  /** What the value is, e.g. "ASN", "Country", "Resolves to" */
  role: string;
  value: string;
  sources: string[];
  /** Set when the value is itself an indicator the analyst can investigate */
  pivot?: string;
}

const MAX_PER_KIND: Record<RelationKind, number> = { network: 5, host: 6, registration: 3, exposure: 2, threat: 5 };

let regionNames: Intl.DisplayNames | null = null;
function countryName(raw: string): string {
  const v = raw.split(',')[0]!.trim();
  if (/^[A-Za-z]{2}$/.test(v)) {
    try {
      regionNames ??= new Intl.DisplayNames(['en'], { type: 'region' });
      return regionNames.of(v.toUpperCase()) ?? v;
    } catch {
      return v;
    }
  }
  return v;
}

function asnOf(raw: string): string | null {
  const m = /\bAS?(\d{1,10})\b/i.exec(raw);
  return m ? `AS${m[1]}` : null;
}

const splitList = (v: string) => v.split(',').map(s => s.trim()).filter(Boolean);

export function buildRelationships(results: EnrichmentResult[], indicator: string): RelationNode[] {
  const nodes = new Map<string, RelationNode>();
  const self = indicator.trim().toLowerCase();

  function add(kind: RelationKind, role: string, value: string, source: string, pivot?: string) {
    const v = value.trim();
    if (!v || v.toLowerCase() === self || /^(none|n\/a|unknown|-)$/i.test(v)) return;
    const id = `${kind}:${role}:${v.toLowerCase()}`;
    const node = nodes.get(id);
    if (node) {
      if (!node.sources.includes(source)) node.sources.push(source);
    } else {
      nodes.set(id, { id, kind, role, value: v, sources: [source], ...(pivot ? { pivot } : {}) });
    }
  }

  for (const r of results.filter(hasData)) {
    const src = r.providerName;
    for (const ip of r.resolvedIps ?? []) add('host', 'Resolves to', ip, src, ip);
    for (const d of r.relatedDomains ?? []) add('host', 'Certificate name', d, src, d.replace(/^\*\./, ''));

    for (const f of r.keyFacts ?? []) {
      switch (f.label) {
        case 'ASN': {
          const asn = asnOf(f.value);
          if (asn) add('network', 'ASN', asn, src, asn);
          break;
        }
        case 'Org': case 'ISP': case 'Holder':
          add('network', 'Operator', f.value, src);
          break;
        case 'Country':
          add('network', 'Country', countryName(f.value), src);
          break;
        case 'Registrar':
          add('registration', 'Registrar', f.value, src);
          break;
        case 'Registrant org':
          add('registration', 'Registrant', f.value, src);
          break;
        case 'Nameservers':
          for (const ns of splitList(f.value)) add('host', 'Nameserver', ns.toLowerCase(), src, ns.toLowerCase());
          break;
        case 'Open ports':
          if (!/^none$/i.test(f.value)) add('exposure', 'Open ports', f.value.replace(/^\d+\s*\((.*)\)$/, '$1'), src);
          break;
        case 'Tags': case 'Threat types': case 'Threat category':
          for (const t of splitList(f.value).slice(0, 4)) add('threat', 'Label', t, src);
          break;
      }
    }
  }

  // Most-corroborated first within each kind, capped so the graph stays legible
  const byKind = new Map<RelationKind, RelationNode[]>();
  for (const n of nodes.values()) byKind.set(n.kind, [...(byKind.get(n.kind) ?? []), n]);
  const out: RelationNode[] = [];
  for (const kind of Object.keys(MAX_PER_KIND) as RelationKind[]) {
    const list = (byKind.get(kind) ?? []).sort((a, b) => b.sources.length - a.sources.length || a.value.localeCompare(b.value));
    out.push(...list.slice(0, MAX_PER_KIND[kind]));
  }
  return out;
}
