import { STORAGE_KEYS, readRaw, writeJson, isRecord } from './storage';
import { DEFAULT_HUNT_SETTINGS } from './hunting';
import type { HuntSettings, Lookback } from './hunting';
import type { Platform, SplunkSource } from '../data/huntQueries';

const PLATFORMS: Platform[] = ['sentinel', 'defender', 'splunk'];
const LOOKBACKS: Lookback[] = ['24h', '7d', '30d', '90d'];

/** Stored settings, with anything missing or malformed replaced by the default. */
export function loadHuntSettings(): HuntSettings {
  const raw = readRaw(STORAGE_KEYS.huntSettings);
  if (!raw) return structuredClone(DEFAULT_HUNT_SETTINGS);
  try {
    const x: unknown = JSON.parse(raw);
    if (!isRecord(x)) return structuredClone(DEFAULT_HUNT_SETTINGS);
    const splunk = { ...DEFAULT_HUNT_SETTINGS.splunk };
    if (isRecord(x.splunk)) {
      for (const k of Object.keys(splunk) as SplunkSource[]) {
        const v = x.splunk[k];
        if (typeof v === 'string' && v.trim()) splunk[k] = v;
      }
    }
    return {
      platform: PLATFORMS.includes(x.platform as Platform) ? (x.platform as Platform) : DEFAULT_HUNT_SETTINGS.platform,
      lookback: LOOKBACKS.includes(x.lookback as Lookback) ? (x.lookback as Lookback) : DEFAULT_HUNT_SETTINGS.lookback,
      splunk,
    };
  } catch {
    return structuredClone(DEFAULT_HUNT_SETTINGS);
  }
}

export function saveHuntSettings(s: HuntSettings): void {
  writeJson(STORAGE_KEYS.huntSettings, s);
}
