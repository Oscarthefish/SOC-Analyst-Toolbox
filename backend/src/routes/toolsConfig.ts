import { Router } from 'express';
import type { Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';

const router = Router();
const DATA_DIR = path.join(process.cwd(), 'data');
const CUSTOM_TOOLS_FILE = path.join(DATA_DIR, 'customTools.json');

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
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(CUSTOM_TOOLS_FILE, JSON.stringify(tools, null, 2), 'utf-8');
    res.json({ ok: true, count: (tools as unknown[]).length });
  } catch {
    res.status(500).json({ error: 'Failed to save custom tools' });
  }
});

export default router;
