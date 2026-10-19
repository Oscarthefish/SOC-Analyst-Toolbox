import { HUNT_TEMPLATES, DEFAULT_SPLUNK_SOURCES } from '../data/huntQueries';
import type { HuntTemplate, IocKind, Platform, SplunkSource } from '../data/huntQueries';

/** Turns indicators and techniques into ready-to-run hunting queries. */

export type Lookback = '24h' | '7d' | '30d' | '90d';
export type HashType = 'md5' | 'sha1' | 'sha256';

export interface HuntSettings {
  platform: Platform;
  lookback: Lookback;
  splunk: Record<SplunkSource, string>;
}

export const DEFAULT_HUNT_SETTINGS: HuntSettings = {
  platform: 'sentinel',
  lookback: '7d',
  splunk: { ...DEFAULT_SPLUNK_SOURCES },
};

export interface IndicatorGroup {
  kind: IocKind;
  hashType?: HashType;
  values: string[];
}

const KIND_OF: Record<string, IocKind | undefined> = {
  ipv4: 'ip', ipv6: 'ip', domain: 'domain', url: 'url', email: 'email', md5: 'hash', sha1: 'hash', sha256: 'hash',
};

/** Group detected indicators by the kind of query they feed; hashes also split by type (different columns). */
export function groupIndicators(items: { type: string; normalised: string }[]): IndicatorGroup[] {
  const groups = new Map<string, IndicatorGroup>();
  for (const { type, normalised } of items) {
    const kind = KIND_OF[type];
    if (!kind) continue;
    const hashType = kind === 'hash' ? (type as HashType) : undefined;
    const key = hashType ? `hash:${hashType}` : kind;
    const g = groups.get(key) ?? { kind, ...(hashType ? { hashType } : {}), values: [] };
    if (!g.values.includes(normalised)) g.values.push(normalised);
    groups.set(key, g);
  }
  const order: IocKind[] = ['ip', 'domain', 'url', 'hash', 'email'];
  return [...groups.values()].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
}

// ── Quoting ────────────────────────────────────────────────────────────────

const kqlString = (v: string) => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const splString = (v: string) => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function hostOf(url: string): string | null {
  try { return new URL(url).hostname || null; } catch { return null; }
}

// ── Rendering ──────────────────────────────────────────────────────────────

const SPL_EARLIEST: Record<Lookback, string> = { '24h': '-24h', '7d': '-7d', '30d': '-30d', '90d': '-90d' };

export function renderQuery(template: HuntTemplate, settings: HuntSettings, group?: IndicatorGroup): string {
  const values = group?.values ?? [];
  const hosts = [...new Set(values.map(hostOf).filter((h): h is string => !!h))];
  const kql = settings.platform !== 'splunk';
  const list = (vals: string[]) => (kql ? `dynamic([${vals.map(kqlString).join(', ')}])` : vals.map(splString).join(', '));

  const tokens: Record<string, string> = {
    iocs: list(values),
    hosts: list(hosts),
    iocsSuffix: values.map(v => splString(`*${v}`)).join(', '),
    iocsLike: values.map(v => splString(`*${v}*`)).join(', '),
    iocsAt: values.map(v => splString(`*@${v}`)).join(', '),
    iocsTerms: values.map(splString).join(' OR '),
    hashField: (group?.hashType ?? 'sha256').toUpperCase(),
    time: settings.platform === 'defender' ? 'Timestamp' : 'TimeGenerated',
    lookback: settings.lookback,
    earliest: SPL_EARLIEST[settings.lookback],
  };

  return template.query.replace(/\{\{(idx:)?([a-zA-Z0-9]+)\}\}/g, (match, idx: string | undefined, name: string) => {
    if (idx) return settings.splunk[name as SplunkSource]?.trim() || DEFAULT_SPLUNK_SOURCES[name as SplunkSource] || match;
    return tokens[name] ?? match;
  });
}

// ── Selection ──────────────────────────────────────────────────────────────

/** T1110 matches T1110.003 and vice versa, so parent and sub-techniques find each other's hunts. */
export function techniqueMatches(a: string, b: string): boolean {
  return a === b || a.split('.')[0] === b.split('.')[0];
}

export interface BuiltHunt {
  key: string;
  template: HuntTemplate;
  query: string;
  group?: IndicatorGroup;
  /** Selected techniques this hunt addresses */
  matched: string[];
}

export function buildHunts(groups: IndicatorGroup[], techniques: string[], settings: HuntSettings): { sweeps: BuiltHunt[]; hunts: BuiltHunt[] } {
  const forPlatform = HUNT_TEMPLATES.filter(t => t.platforms.includes(settings.platform));
  const matchedOf = (t: HuntTemplate) => techniques.filter(sel => t.techniques.some(x => techniqueMatches(sel, x)));

  const sweeps: BuiltHunt[] = [];
  for (const group of groups) {
    for (const t of forPlatform) {
      if (t.ioc !== group.kind) continue;
      if (t.hashTypes && group.hashType && !t.hashTypes.includes(group.hashType)) continue;
      sweeps.push({ key: `${t.id}:${group.hashType ?? group.kind}`, template: t, query: renderQuery(t, settings, group), group, matched: matchedOf(t) });
    }
  }

  const hunts = forPlatform
    .filter(t => !t.ioc)
    .map(t => ({ t, matched: matchedOf(t) }))
    .filter(x => x.matched.length > 0)
    .map(({ t, matched }) => ({ key: t.id, template: t, query: renderQuery(t, settings), matched }));

  return { sweeps, hunts };
}

/** Techniques that have at least one technique hunt on the platform (for the coverage view). */
export function huntableTechniques(platform: Platform): Set<string> {
  const ids = new Set<string>();
  for (const t of HUNT_TEMPLATES) if (!t.ioc && t.platforms.includes(platform)) for (const id of t.techniques) ids.add(id);
  return ids;
}
