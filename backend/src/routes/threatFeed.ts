import { Router } from 'express';
import type { Request, Response } from 'express';
import { config } from '../config.js';

const router = Router();
const TIMEOUT_MS = 15_000;
const INTER_QUERY_DELAY_MS = 1_200;

interface ExploreIndicator {
  iid?: number;
  indicator?: string;
  type?: string;
  risk?: string;
  stamp_added?: string;
  stamp_updated?: string;
  stamp_seen?: string;
  summary?: {
    threats?: Array<{ name?: string }>;
    feeds?: Array<{ name?: string }>;
    properties?: { geo?: { country?: string } };
  };
}

interface ExploreResponse {
  results?: ExploreIndicator[];
  query?: string;
  error?: string;
}

interface FeedSection {
  label: string;
  query: string;
  indicators: ExploreIndicator[];
  error?: string;
}

const EXPLORE_SECTIONS = [
  { label: 'Critical Threats',          query: 'risk=critical and seen=month' },
  { label: 'High Risk Infrastructure',  query: 'risk=high+ and type=ip,ipv6 and seen=week' },
  { label: 'High Risk Domains & URLs',  query: 'risk=high+ and type=domain,url and seen=week' },
];

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function exploreQuery(q: string, apiKey: string, limit = 15): Promise<{ indicators: ExploreIndicator[]; error?: string }> {
  const params = new URLSearchParams({ q, key: apiKey, limit: String(limit), pretty: '0' });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(`https://pulsedive.com/api/explore.php?${params}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeout);
    if (r.status === 401 || r.status === 403) return { indicators: [], error: 'Invalid API key.' };
    if (r.status === 429) return { indicators: [], error: 'Rate limit reached — try again in a minute.' };
    if (!r.ok) return { indicators: [], error: `HTTP ${r.status}` };
    const json = await r.json() as ExploreResponse;
    if (json.error) return { indicators: [], error: json.error };
    return { indicators: json.results ?? [] };
  } catch (e) {
    clearTimeout(timeout);
    const isTimeout = e instanceof Error && e.name === 'AbortError';
    return { indicators: [], error: isTimeout ? 'Request timed out.' : String(e) };
  }
}

router.get('/threat-feed', async (_req: Request, res: Response) => {
  const apiKey = config.pulsedive.apiKey;
  if (!apiKey) {
    res.status(402).json({ error: 'Pulsedive API key is not configured. Add it in the API Keys tab to enable the threat feed.' });
    return;
  }

  // Run queries sequentially to respect rate limits
  const sectionResults: Array<{ indicators: ExploreIndicator[]; error?: string }> = [];
  for (let i = 0; i < EXPLORE_SECTIONS.length; i++) {
    if (i > 0) await delay(INTER_QUERY_DELAY_MS);
    sectionResults.push(await exploreQuery(EXPLORE_SECTIONS[i].query, apiKey, 15));
  }

  // If every section errored with the same error, surface it at route level
  if (sectionResults.every(r => r.error)) {
    const firstError = sectionResults[0].error!;
    const statusCode = firstError.includes('Invalid API key') ? 401 : firstError.includes('Rate limit') ? 429 : 500;
    res.status(statusCode).json({ error: `Pulsedive: ${firstError}` });
    return;
  }

  const sections: FeedSection[] = EXPLORE_SECTIONS.map((s, i) => ({
    label: s.label,
    query: s.query,
    indicators: sectionResults[i].indicators,
    ...(sectionResults[i].error ? { error: sectionResults[i].error } : {}),
  }));

  const totalCount = sections.reduce((n, s) => n + s.indicators.length, 0);

  res.json({
    sections,
    totalCount,
    fetchedAt: new Date().toISOString(),
    source: 'Pulsedive',
  });
});

export default router;
