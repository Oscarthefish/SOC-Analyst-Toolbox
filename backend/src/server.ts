import express from 'express';
import cors from 'cors';
import { config } from './config.js';
import healthRouter from './routes/health.js';
import enrichRouter from './routes/enrich.js';
import keysRouter from './routes/keys.js';
import analyseRouter from './routes/analyse.js';
import analyseEmailHeaderRouter from './routes/analyseEmailHeader.js';
import threatFeedRouter from './routes/threatFeed.js';
import threatBriefingRouter from './routes/threatBriefing.js';
import toolsConfigRouter from './routes/toolsConfig.js';

const app = express();

// CORS — allow frontend dev servers
app.use(
  cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'],
    methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
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

const port = config.port;
const host = '127.0.0.1';
app.listen(port, host, () => {
  const providerList = config.configuredProviders.length > 0
    ? config.configuredProviders.join(', ')
    : 'none';
  console.log(`[server] SOC Analyst Toolbox API running on http://${host}:${port}`);
  console.log(`[server] Configured providers: ${providerList}`);
  console.log(`[server] URL submission: ${config.enableUrlSubmission ? 'ENABLED' : 'disabled'}`);
  console.log(`[server] Cache TTL: ${config.cacheTtlMinutes} minutes`);
});
