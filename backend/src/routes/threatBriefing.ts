import { Router } from 'express';
import type { Request, Response } from 'express';
import fetch from 'node-fetch';

const router = Router();
const TIMEOUT_MS = 15_000;
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

export interface ThreatEvent {
  id: string;
  type: 'cve' | 'ransomware' | 'malware' | 'advisory';
  title: string;
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'informational';
  source: string;
  sourceUrl: string;
  publishedAt: string;
  tags: string[];
  cve?: string;
  ransomwareGroup?: string;
  affectedProducts?: string[];
  victim?: string;
  country?: string;
  sector?: string;
}

interface BriefingCache {
  events: ThreatEvent[];
  fetchedAt: string;
  errors: Record<string, string>;
}

let briefingCache: BriefingCache | null = null;
let cacheTs = 0;

// ── CISA KEV ─────────────────────────────────────────────────────────────────

interface KevVuln {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

async function fetchKevEvents(): Promise<ThreatEvent[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: controller.signal, headers: { Accept: 'application/json' } },
    );
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json() as { vulnerabilities?: KevVuln[] };
    const vulns = json.vulnerabilities ?? [];
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 30);

    return vulns
      .filter(v => v.dateAdded && new Date(v.dateAdded) >= cutoff)
      .sort((a, b) => (b.dateAdded ?? '').localeCompare(a.dateAdded ?? ''))
      .slice(0, 25)
      .map(v => ({
        id: `kev-${v.cveID ?? 'unknown'}`,
        type: 'cve' as const,
        title: `${v.cveID ?? 'CVE'} — ${v.vendorProject ?? ''} ${v.product ?? ''}`.trim(),
        summary: v.shortDescription ?? `${v.cveID} is in the CISA Known Exploited Vulnerabilities catalogue.`,
        severity: 'critical' as const,
        source: 'CISA KEV',
        sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        publishedAt: v.dateAdded ? new Date(v.dateAdded).toISOString() : new Date().toISOString(),
        tags: [
          'actively-exploited',
          ...(v.knownRansomwareCampaignUse === 'Known' ? ['ransomware'] : []),
        ],
        cve: v.cveID,
        affectedProducts: [v.vendorProject, v.product].filter(Boolean) as string[],
      }));
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// ── Ransomware.live ───────────────────────────────────────────────────────────

interface RansomwareVictim {
  post_title?: string;
  group_name?: string;
  website?: string;
  published?: string;
  country?: string;
  activity?: string;
  post_url?: string;
  description?: string;
}

async function fetchRansomwareEvents(): Promise<ThreatEvent[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch('https://api.ransomware.live/recentvictims', {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const victims = await res.json() as RansomwareVictim[];
    if (!Array.isArray(victims)) throw new Error('Unexpected response format');

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 7);

    return victims
      .filter(v => v.published && new Date(v.published) >= cutoff)
      .sort((a, b) => (b.published ?? '').localeCompare(a.published ?? ''))
      .slice(0, 30)
      .map((v, i) => ({
        id: `ransomware-${i}-${v.group_name ?? 'unknown'}-${(v.website ?? '').replace(/[^a-z0-9]/gi, '')}`,
        type: 'ransomware' as const,
        title: `${v.group_name ?? 'Unknown group'}: ${v.post_title ?? v.website ?? 'Unknown victim'}`,
        summary: v.description
          ? v.description.slice(0, 200)
          : `${v.group_name ?? 'A ransomware group'} claimed ${v.post_title ?? v.website ?? 'an organisation'}${v.country ? ` (${v.country})` : ''}${v.activity ? ` in the ${v.activity} sector` : ''}.`,
        severity: 'high' as const,
        source: 'Ransomware.live',
        sourceUrl: v.post_url ?? 'https://www.ransomware.live',
        publishedAt: v.published ? new Date(v.published).toISOString() : new Date().toISOString(),
        tags: ['ransomware', ...(v.activity ? [v.activity.toLowerCase().replace(/\s+/g, '-')] : [])],
        ransomwareGroup: v.group_name,
        victim: v.post_title ?? v.website,
        country: v.country,
        sector: v.activity,
      }));
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// ── Handler ───────────────────────────────────────────────────────────────────

router.get('/threat-briefing', async (_req: Request, res: Response): Promise<void> => {
  // Return cached data if fresh
  if (briefingCache && Date.now() - cacheTs < CACHE_TTL_MS) {
    res.json(briefingCache);
    return;
  }

  const errors: Record<string, string> = {};
  const allEvents: ThreatEvent[] = [];

  const [kevResult, ransomwareResult] = await Promise.allSettled([
    fetchKevEvents(),
    fetchRansomwareEvents(),
  ]);

  if (kevResult.status === 'fulfilled') {
    allEvents.push(...kevResult.value);
  } else {
    errors['CISA KEV'] = kevResult.reason instanceof Error ? kevResult.reason.message : 'Failed';
  }

  if (ransomwareResult.status === 'fulfilled') {
    allEvents.push(...ransomwareResult.value);
  } else {
    errors['Ransomware.live'] = ransomwareResult.reason instanceof Error ? ransomwareResult.reason.message : 'Failed';
  }

  // Sort: critical first, then by date descending
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, informational: 3 };
  allEvents.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    return b.publishedAt.localeCompare(a.publishedAt);
  });

  const response: BriefingCache = {
    events: allEvents,
    fetchedAt: new Date().toISOString(),
    errors,
  };

  briefingCache = response;
  cacheTs = Date.now();

  res.json(response);
});

export default router;
