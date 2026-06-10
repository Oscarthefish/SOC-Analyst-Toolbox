import { Router } from 'express';
import type { Request, Response } from 'express';
import { config } from '../config.js';

const router = Router();

router.get('/health', (_req: Request, res: Response) => {
  res.json({
    ok: true,
    service: 'soc-analyst-toolbox-api',
    configuredProviders: config.configuredProviders,
    flags: {
      enableUrlSubmission: config.enableUrlSubmission,
      enableHighRiskEnrichment: config.enableHighRiskEnrichment,
    },
  });
});

export default router;
