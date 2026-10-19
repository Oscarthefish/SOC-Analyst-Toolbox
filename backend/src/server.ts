import { installFetchDefaults } from './lib/http.js';
import { config } from './config.js';
import { flushSync as flushCache } from './cache.js';
import { createApp } from './app.js';

installFetchDefaults();

const port = config.port;
const host = '127.0.0.1';

createApp().listen(port, host, () => {
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
