import { Router } from 'express';
import type { Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { reloadConfig, PROVIDER_KEYS } from '../config.js';
import type { ProviderKeyEnv } from '../config.js';

const router = Router();

/**
 * Allowlist of env vars that may be read or written via this endpoint, derived from
 * the provider registry. Intentionally excludes PORT, feature flags and other settings.
 */
const ALLOWED_KEYS: readonly ProviderKeyEnv[] = PROVIDER_KEYS.map(p => p.env);

type AllowedKey = ProviderKeyEnv;

/** The .env file holding API keys: backend/.env by default, or ENV_FILE (used by tests). */
function envFilePath(): string {
  return process.env.ENV_FILE ?? path.resolve(process.cwd(), '.env');
}

/**
 * Write the .env file atomically (temp file + rename) and readable only by the
 * current user, since it holds API keys.
 */
async function writeEnvFile(content: string): Promise<void> {
  const target = envFilePath();
  const tmp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(tmp, content, { encoding: 'utf-8', mode: 0o600 });
  await fs.rename(tmp, target);
  await fs.chmod(target, 0o600);
}

/**
 * Parse a .env file into a Map of key -> value.
 * Lines that are comments or blank are stored with a sentinel key so they are
 * preserved during a write-back (they are handled separately).
 */
function parseEnvLines(content: string): string[] {
  return content ? content.split('\n') : [];
}

/**
 * Given the current lines of a .env file, set `key=value`, either by
 * replacing an existing line or appending a new one.
 */
function upsertLine(lines: string[], key: string, value: string): string[] {
  const prefix = `${key}=`;
  let replaced = false;
  const updated = lines.map(line => {
    if (line.startsWith(prefix)) {
      replaced = true;
      return `${prefix}${value}`;
    }
    return line;
  });
  if (!replaced) {
    updated.push(`${prefix}${value}`);
  }
  return updated;
}

/**
 * Read the .env file and return each allowed key's configured status (boolean).
 * Returns all false if the file does not exist.
 */
router.get('/keys', async (_req: Request, res: Response) => {
  let content = '';
  try {
    content = await fs.readFile(envFilePath(), 'utf-8');
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error('[keys] Failed to read .env:', (err as Error).message);
      res.status(500).json({ error: 'Failed to read configuration.' });
      return;
    }
    // File does not exist — return all false
  }

  // Parse key=value pairs from the file
  const fileValues: Record<string, string> = {};
  for (const line of parseEnvLines(content)) {
    const eqIdx = line.indexOf('=');
    if (eqIdx === -1) continue;
    const k = line.slice(0, eqIdx).trim();
    const v = line.slice(eqIdx + 1).trim();
    fileValues[k] = v;
  }

  const keys: Record<AllowedKey, boolean> = {} as Record<AllowedKey, boolean>;
  for (const k of ALLOWED_KEYS) {
    keys[k] = Boolean(fileValues[k] && fileValues[k].length > 0);
  }

  res.json({ keys });
});

/**
 * Write a single API key to .env.
 * Body: { key: string; value: string }
 */
router.post('/keys', async (req: Request, res: Response) => {
  const { key, value } = req.body as { key?: unknown; value?: unknown };

  if (typeof key !== 'string' || typeof value !== 'string') {
    res.status(400).json({ ok: false, error: 'key and value must be strings.' });
    return;
  }

  if (!(ALLOWED_KEYS as readonly string[]).includes(key)) {
    res.status(400).json({ ok: false, error: `Unknown key: ${key}` });
    return;
  }

  // Strip newlines and null bytes to prevent .env injection; trim like the reader does
  const safeValue = value.replace(/[\r\n\0]/g, '').trim();

  let existingContent = '';
  try {
    existingContent = await fs.readFile(envFilePath(), 'utf-8');
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error('[keys] Failed to read .env for update:', (err as Error).message);
      res.status(500).json({ ok: false, error: 'Failed to read configuration file.' });
      return;
    }
    // File doesn't exist yet — start fresh
  }

  const lines = parseEnvLines(existingContent);
  const updatedLines = upsertLine(lines, key, safeValue);
  const updatedContent = updatedLines.join('\n');

  try {
    await writeEnvFile(updatedContent);
  } catch (err: unknown) {
    console.error('[keys] Failed to write .env:', (err as Error).message);
    res.status(500).json({ ok: false, error: 'Failed to write configuration file.' });
    return;
  }

  // Update process.env so enrichment picks up the new value immediately
  process.env[key] = safeValue;

  // Reload the exported config object in place
  reloadConfig();

  const configured = safeValue.length > 0;
  res.json({ ok: true, key, configured });
});

export default router;
