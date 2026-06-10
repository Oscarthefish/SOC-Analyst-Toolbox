import fetch from 'node-fetch';

const OLLAMA_BASE = 'http://localhost:11434';
const GENERATE_TIMEOUT_MS = 90_000;

interface OllamaGenerateResponse {
  model: string;
  response: string;
  done: boolean;
}

interface OllamaTagsResponse {
  models?: Array<{ name: string }>;
}

export async function ollamaGenerate(model: string, prompt: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GENERATE_TIMEOUT_MS);
  try {
    const res = await fetch(`${OLLAMA_BASE}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`Ollama returned HTTP ${res.status}`);
    const data = await res.json() as OllamaGenerateResponse;
    return data.response.trim();
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

/**
 * Returns the resolved full model name (e.g. "qwen2.5:7b-instruct") if the
 * model is available, or null if Ollama is unreachable or the model is missing.
 * Matches by base name prefix so "qwen2.5" resolves to "qwen2.5:7b-instruct".
 */
export async function resolveOllamaModel(model: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3_000);
    const res = await fetch(`${OLLAMA_BASE}/api/tags`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = await res.json() as OllamaTagsResponse;
    const modelBase = model.split(':')[0] ?? model;
    // Prefer exact match, fall back to prefix match
    const exact = data.models?.find(m => m.name === model);
    if (exact) return exact.name;
    const prefix = data.models?.find(m => m.name.startsWith(modelBase));
    return prefix?.name ?? null;
  } catch {
    return null;
  }
}
