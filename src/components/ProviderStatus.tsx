import { useState, useEffect, useCallback } from 'react';
import type { HealthResponse } from '../types/enrichment';
import { checkBackendHealth } from '../lib/apiClient';

interface ProviderStatusProps {
  onHealthChange?: (health: HealthResponse | null) => void;
}

export function ProviderStatus({ onHealthChange }: ProviderStatusProps) {
  const [health, setHealth] = useState<HealthResponse | null | undefined>(undefined);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [checking, setChecking] = useState(false);

  const doCheck = useCallback(async () => {
    setChecking(true);
    try {
      const result = await checkBackendHealth();
      setHealth(result);
      setLastChecked(new Date());
      onHealthChange?.(result);
    } finally {
      setChecking(false);
    }
  }, [onHealthChange]);

  useEffect(() => { void doCheck(); }, [doCheck]);
  useEffect(() => {
    const interval = setInterval(() => { void doCheck(); }, 30_000);
    return () => clearInterval(interval);
  }, [doCheck]);

  const refreshBtn = (label: string, cls: string) => (
    <button
      onClick={() => void doCheck()}
      disabled={checking}
      className={`text-xs px-2.5 py-1 rounded-lg border font-medium shrink-0 transition-colors disabled:opacity-50 ${cls}`}
    >
      {checking ? 'Checking…' : label}
    </button>
  );

  if (health === undefined) {
    return (
      <div className="flex items-center gap-2 text-xs text-fg-3">
        <span className="w-2 h-2 rounded-full bg-line-strong animate-pulse shrink-0" />
        Checking enrichment backend…
      </div>
    );
  }

  if (health === null) {
    return (
      <div className="flex items-center justify-between gap-3 bg-warn-bg border border-warn-line rounded-lg px-3 py-2">
        <div className="flex items-center gap-2 text-xs text-warn-fg">
          <span className="w-2 h-2 rounded-full bg-warn shrink-0" />
          <span>
            <strong>Backend offline</strong> — static tool links still work. Run{' '}
            <code className="bg-warn-line/40 px-1 rounded font-mono">npm run backend:dev</code> to enable API enrichment.
          </span>
        </div>
        {refreshBtn('Retry', 'border-warn-line text-warn-fg hover:bg-warn-line/30')}
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between gap-3 bg-ok-bg border border-ok-line rounded-lg px-3 py-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ok-fg">
        <span className="flex items-center gap-1.5 font-semibold">
          <span className="w-2 h-2 rounded-full bg-ok shrink-0" />
          Backend online
        </span>
        {health.configuredProviders.length > 0 ? (
          <span className="text-ok-fg/80">{health.configuredProviders.length} providers configured</span>
        ) : (
          <span className="text-warn-fg">No API keys configured</span>
        )}
        {lastChecked && (
          <span className="text-ok-fg/60 font-mono">{lastChecked.toLocaleTimeString()}</span>
        )}
      </div>
      {refreshBtn('Refresh', 'border-ok-line text-ok-fg hover:bg-ok-line/30')}
    </div>
  );
}
