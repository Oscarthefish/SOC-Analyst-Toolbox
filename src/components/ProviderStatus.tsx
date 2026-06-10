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
      <div className="flex items-center gap-2 text-xs text-[#667085]">
        <span className="w-2 h-2 rounded-full bg-[#d0d5dd] animate-pulse shrink-0" />
        Checking enrichment backend…
      </div>
    );
  }

  if (health === null) {
    return (
      <div className="flex items-center justify-between gap-3 bg-[#fffaeb] border border-[#fedf89] rounded-lg px-3 py-2">
        <div className="flex items-center gap-2 text-xs text-[#b54708]">
          <span className="w-2 h-2 rounded-full bg-[#dc6803] shrink-0" />
          <span>
            <strong>Backend offline</strong> — static tool links still work. Run{' '}
            <code className="bg-[#fedf89]/40 px-1 rounded font-mono">npm run backend:dev</code> to enable API enrichment.
          </span>
        </div>
        {refreshBtn('Retry', 'border-[#fedf89] text-[#b54708] hover:bg-[#fedf89]/30')}
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between gap-3 bg-[#ecfdf3] border border-[#abefc6] rounded-lg px-3 py-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#067647]">
        <span className="flex items-center gap-1.5 font-semibold">
          <span className="w-2 h-2 rounded-full bg-[#079455] shrink-0" />
          Backend online
        </span>
        {health.configuredProviders.length > 0 ? (
          <span className="text-[#079455]/80">{health.configuredProviders.length} providers configured</span>
        ) : (
          <span className="text-[#b54708]">No API keys configured</span>
        )}
        {lastChecked && (
          <span className="text-[#067647]/60 font-mono">{lastChecked.toLocaleTimeString()}</span>
        )}
      </div>
      {refreshBtn('Refresh', 'border-[#abefc6] text-[#067647] hover:bg-[#abefc6]/30')}
    </div>
  );
}
