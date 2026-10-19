import type { EnrichRequest, EnrichmentResponse, HealthResponse, EnrichmentResult, OverallAssessment } from '../types/enrichment';
import type { AnalysisRequest, AnalysisResponse, EmailHeaderAnalysisRequest, EmailHeaderAnalysisResponse } from '../types/analysis';

// Relative: the Vite dev/preview server proxies /api to the local backend
const BACKEND_URL = '';
const ENRICH_TIMEOUT_MS = 30_000;
const ANALYSE_TIMEOUT_MS = 120_000;
const SHORT_TIMEOUT_MS = 5_000;

export async function checkBackendHealth(): Promise<HealthResponse | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    const res = await fetch(`${BACKEND_URL}/api/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch {
    return null;
  }
}

export async function getKeyStatus(): Promise<Record<string, boolean> | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SHORT_TIMEOUT_MS);
    const res = await fetch(`${BACKEND_URL}/api/config/keys`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = (await res.json()) as { keys: Record<string, boolean> };
    return data.keys;
  } catch {
    return null;
  }
}

export async function saveApiKey(
  key: string,
  value: string,
): Promise<{ ok: boolean; error?: string } | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SHORT_TIMEOUT_MS);
    const res = await fetch(`${BACKEND_URL}/api/config/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, value }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      return { ok: false, error: body.error ?? `HTTP ${res.status}` };
    }
    return (await res.json()) as { ok: boolean; error?: string };
  } catch (err) {
    console.error('[apiClient] saveApiKey failed:', err);
    return null;
  }
}

export async function runAutoAnalysis(request: AnalysisRequest): Promise<AnalysisResponse | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ANALYSE_TIMEOUT_MS);
    const res = await fetch(`${BACKEND_URL}/api/analyse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      console.error('[apiClient] Auto analysis failed:', res.status, res.statusText);
      return null;
    }
    return (await res.json()) as AnalysisResponse;
  } catch (err) {
    console.error('[apiClient] Auto analysis request failed:', err);
    return null;
  }
}

// ── Streaming analysis ────────────────────────────────────────────────────

export interface SseEvent {
  event: string;
  data: string;
}

/** Split buffered SSE text into complete events plus the unfinished remainder. */
export function parseSse(buffer: string): { events: SseEvent[]; rest: string } {
  const blocks = buffer.replace(/\r\n/g, '\n').split('\n\n');
  const rest = blocks.pop() ?? '';
  const events: SseEvent[] = [];
  for (const block of blocks) {
    let event = 'message';
    const data: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    }
    if (data.length > 0) events.push({ event, data: data.join('\n') });
  }
  return { events, rest };
}

export interface AnalysisProgress {
  /** Providers being queried, in request order */
  providers: string[];
  /** Results received so far */
  results: EnrichmentResult[];
  /** Verdict, available once all providers have answered (before the narrative) */
  overall?: OverallAssessment;
}

/**
 * Run an analysis via /api/analyse/stream, reporting provider results and the verdict
 * as they arrive. Falls back to the non-streaming endpoint if streaming is unavailable.
 */
export async function streamAutoAnalysis(
  request: AnalysisRequest,
  onProgress: (progress: AnalysisProgress) => void,
): Promise<AnalysisResponse | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ANALYSE_TIMEOUT_MS);
  try {
    const res = await fetch(`${BACKEND_URL}/api/analyse/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    if (!res.ok || !res.body || !res.headers.get('content-type')?.includes('text/event-stream')) {
      clearTimeout(timeout);
      return runAutoAnalysis(request);
    }

    const progress: AnalysisProgress = { providers: [], results: [] };
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const { events, rest } = parseSse(buffer + value);
      buffer = rest;
      for (const { event, data } of events) {
        const payload: unknown = JSON.parse(data);
        if (event === 'start') {
          progress.providers = (payload as { providers: string[] }).providers;
        } else if (event === 'provider') {
          progress.results = [...progress.results, payload as EnrichmentResult];
        } else if (event === 'assessment') {
          progress.overall = (payload as { overall: OverallAssessment }).overall;
        } else if (event === 'done') {
          return payload as AnalysisResponse;
        } else if (event === 'error') {
          throw new Error((payload as { error: string }).error);
        }
        onProgress({ ...progress });
      }
    }
    return null;
  } catch (err) {
    console.error('[apiClient] Streaming analysis failed:', err);
    if (err instanceof Error && err.name !== 'AbortError' && err.name !== 'TypeError') throw err;
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export async function runEmailHeaderAnalysis(
  request: EmailHeaderAnalysisRequest,
): Promise<EmailHeaderAnalysisResponse | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ANALYSE_TIMEOUT_MS);
    const res = await fetch(`${BACKEND_URL}/api/analyse-email-header`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      console.error('[apiClient] Email header analysis failed:', res.status, res.statusText);
      return null;
    }
    return (await res.json()) as EmailHeaderAnalysisResponse;
  } catch (err) {
    console.error('[apiClient] Email header analysis request failed:', err);
    return null;
  }
}

export async function runEnrichment(request: EnrichRequest): Promise<EnrichmentResponse | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ENRICH_TIMEOUT_MS);
    const res = await fetch(`${BACKEND_URL}/api/enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
      console.error('[apiClient] Enrichment failed:', res.status, res.statusText);
      return null;
    }
    return (await res.json()) as EnrichmentResponse;
  } catch (err) {
    console.error('[apiClient] Enrichment request failed:', err);
    return null;
  }
}
