import express from 'express';
import { installFetchDefaults } from './lib/http.js';
import cors from 'cors';
import { config } from './config.js';
import { flushSync as flushCache } from './cache.js';
import healthRouter from './routes/health.js';
import enrichRouter from './routes/enrich.js';
import keysRouter from './routes/keys.js';
import analyseRouter from './routes/analyse.js';
import analyseEmailHeaderRouter from './routes/analyseEmailHeader.js';
import threatFeedRouter from './routes/threatFeed.js';
import threatBriefingRouter from './routes/threatBriefing.js';
import toolsConfigRouter from './routes/toolsConfig.js';

installFetchDefaults();

const app = express();

const port = config.port;
const host = '127.0.0.1';

// Frontend origins allowed to call the API (Vite dev + preview by default)
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173,http://localhost:5174,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:4173')
    .split(',').map(o => o.trim()).filter(Boolean),
);
const allowedHosts = new Set([`localhost:${port}`, `127.0.0.1:${port}`]);

// Reject requests not addressed to this machine by name. Blocks DNS rebinding,
// where an attacker's domain resolves to 127.0.0.1 and the browser sends Host: evil.example.
app.use((req, res, next) => {
  if (!allowedHosts.has(req.headers.host ?? '')) {
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

// Body parsing
app.use(express.json({ limit: '1mb' }));

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
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, host, () => {
  const providerList = config.configuredProviders.length > 0
    ? config.configuredProviders.join(', ')
    : 'none';
  console.log(`[server] SOC Analyst Toolbox API running on http://${host}:${port}`);
  console.log(`[server] Configured providers: ${providerList}`);
  console.log(`[server] URL submission: ${config.enableUrlSubmission ? 'ENABLED' : 'disabled'}`);
  console.log(`[server] Cache TTL: ${config.cacheTtlMinutes} minutes`);
});

// Persist any pending cache writes before exiting (Ctrl+C, tsx watch restarts)
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    flushCache();
    process.exit(0);
  });
}
