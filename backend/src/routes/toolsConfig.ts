import { Router } from 'express';
import type { Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';

const router = Router();
const DATA_DIR = path.join(process.cwd(), 'data');
const CUSTOM_TOOLS_FILE = path.join(DATA_DIR, 'customTools.json');
const MAX_TOOLS = 500;

const STRING_FIELDS = ['id', 'name', 'category', 'description', 'urlTemplate', 'whyUse', 'lookFor', 'riskNote'] as const;
const ARRAY_FIELDS = ['inputTypes', 'workflows', 'tags'] as const;
const RISKS = new Set(['low', 'medium', 'high']);
const ACCESS = new Set(['none', 'free_account', 'trial', 'paid', 'mixed']);

/**
 * Validate one custom tool and return a copy containing only known fields.
 * urlTemplate is rendered into <a href>, so only http(s) URLs are accepted —
 * anything else (javascript:, data:) would be stored XSS.
 */
function sanitiseTool(raw: unknown, index: number): { tool?: Record<string, unknown>; error?: string } {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { error: `Tool ${index}: must be an object.` };
  }
  const t = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};

  for (const f of STRING_FIELDS) {
    const v = t[f] ?? '';
    if (typeof v !== 'string' || v.length > 2048) return { error: `Tool ${index}: ${f} must be a string of at most 2048 characters.` };
    out[f] = v;
  }
  for (const f of ARRAY_FIELDS) {
    const v = t[f] ?? [];
    if (!Array.isArray(v) || v.length > 50 || !v.every(x => typeof x === 'string' && x.length <= 100)) {
      return { error: `Tool ${index}: ${f} must be an array of short strings.` };
    }
    out[f] = v;
  }

  if (!/^[A-Za-z0-9_-]{1,64}$/.test(out.id as string)) return { error: `Tool ${index}: id must be 1-64 letters, digits, _ or -.` };
  if (!(out.name as string).trim()) return { error: `Tool ${index}: name is required.` };
  if (!/^https?:\/\//i.test(out.urlTemplate as string)) return { error: `Tool ${index}: urlTemplate must start with http:// or https://.` };

  const risk = t.submissionRisk ?? 'high';
  const access = t.requiresAccount ?? 'none';
  if (typeof risk !== 'string' || !RISKS.has(risk)) return { error: `Tool ${index}: submissionRisk must be low, medium or high.` };
  if (typeof access !== 'string' || !ACCESS.has(access)) return { error: `Tool ${index}: invalid requiresAccount.` };
  out.submissionRisk = risk;
  out.requiresAccount = access;

  return { tool: out };
}

router.get('/tools/custom', async (_req: Request, res: Response): Promise<void> => {
  try {
    const raw = await fs.readFile(CUSTOM_TOOLS_FILE, 'utf-8');
    res.json(JSON.parse(raw) as unknown[]);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      res.json([]);
    } else {
      res.status(500).json({ error: 'Failed to read custom tools' });
    }
  }
});

router.put('/tools/custom', async (req: Request, res: Response): Promise<void> => {
  const tools = req.body as unknown;
  if (!Array.isArray(tools)) {
    res.status(400).json({ error: 'Body must be an array' });
    return;
  }
  if (tools.length > MAX_TOOLS) {
    res.status(400).json({ error: `At most ${MAX_TOOLS} custom tools are supported.` });
    return;
  }
  const clean: Record<string, unknown>[] = [];
  for (const [i, raw] of tools.entries()) {
    const { tool, error } = sanitiseTool(raw, i);
    if (error || !tool) {
      res.status(400).json({ error });
      return;
    }
    clean.push(tool);
  }
  if (new Set(clean.map(t => t.id)).size !== clean.length) {
    res.status(400).json({ error: 'Tool ids must be unique.' });
    return;
  }
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmp = `${CUSTOM_TOOLS_FILE}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(clean, null, 2), 'utf-8');
    await fs.rename(tmp, CUSTOM_TOOLS_FILE);
    res.json({ ok: true, count: clean.length });
  } catch {
    res.status(500).json({ error: 'Failed to save custom tools' });
  }
});

export default router;
