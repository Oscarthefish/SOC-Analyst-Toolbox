import type { EnrichRequest, EnrichmentResponse, HealthResponse } from '../types/enrichment';
import type { AnalysisRequest, AnalysisResponse, EmailHeaderAnalysisRequest, EmailHeaderAnalysisResponse } from '../types/analysis';

const BACKEND_URL = 'http://localhost:8787';
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
