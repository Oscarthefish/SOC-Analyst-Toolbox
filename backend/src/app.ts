import express from 'express';
import cors from 'cors';
import healthRouter from './routes/health.js';
import enrichRouter from './routes/enrich.js';
import keysRouter from './routes/keys.js';
import analyseRouter from './routes/analyse.js';
import analyseEmailHeaderRouter from './routes/analyseEmailHeader.js';
import threatFeedRouter from './routes/threatFeed.js';
import threatBriefingRouter from './routes/threatBriefing.js';
import toolsConfigRouter from './routes/toolsConfig.js';

/** Build the API app (no listening), so it can be started by server.ts or by tests. */
export function createApp(): express.Express {
  const app = express();

  // Frontend origins allowed to call the API (Vite dev + preview by default)
  const allowedOrigins = new Set(
    (process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173,http://localhost:5174,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:4173')
      .split(',').map(o => o.trim()).filter(Boolean),
  );

  // Reject requests not addressed to this machine by name. Blocks DNS rebinding,
  // where an attacker's domain resolves to 127.0.0.1 and the browser sends Host: evil.example.
  app.use((req, res, next) => {
    const port = req.socket.localPort;
    const host = req.headers.host ?? '';
    if (host !== `localhost:${port}` && host !== `127.0.0.1:${port}`) {
      res.status(403).json({ error: 'Forbidden host.' });
      return;
    }
    next();
  });

  // Browsers always send Origin on cross-origin and on mutating requests. Reject any
  // origin that isn't the local frontend; requests without Origin (curl, server-side) pass.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins.has(origin)) {
      res.status(403).json({ error: 'Forbidden origin.' });
      return;
    }
    next();
  });

  app.use(
    cors({
      origin: [...allowedOrigins],
      methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
      allowedHeaders: ['Content-Type'],
    }),
  );

  // Body parsing. Express 5 leaves req.body undefined when there is no JSON body;
  // default it to {} so route validation returns 400 rather than throwing.
  app.use(express.json({ limit: '1mb' }));
  app.use((req, _res, next) => {
    req.body ??= {};
    next();
  });

  // Mount routes
  app.use('/api', healthRouter);
  app.use('/api', enrichRouter);
  app.use('/api', analyseRouter);
  app.use('/api', analyseEmailHeaderRouter);
  app.use('/api', threatFeedRouter);
  app.use('/api', threatBriefingRouter);
  app.use('/api/config', keysRouter);
  app.use('/api', toolsConfigRouter);

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found.' });
  });

  // Error handler
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    // Client errors raised by middleware (malformed JSON, oversized body) carry a 4xx status
    const status = (err as { status?: number }).status;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      res.status(status).json({ error: status === 413 ? 'Request body too large.' : 'Malformed request body.' });
      return;
    }
    console.error('[server] Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  });

  return app;
}
