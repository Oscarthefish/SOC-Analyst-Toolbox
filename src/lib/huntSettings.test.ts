import { describe, it, expect, beforeEach } from 'vitest';
import { installMemoryStorage } from '../test/memoryStorage';
import { loadHuntSettings, saveHuntSettings } from './huntSettings';
import { DEFAULT_HUNT_SETTINGS } from './hunting';

describe('hunt settings storage', () => {
  beforeEach(() => installMemoryStorage());

  it('round-trips and falls back field by field', () => {
    expect(loadHuntSettings()).toEqual(DEFAULT_HUNT_SETTINGS);
    saveHuntSettings({ ...DEFAULT_HUNT_SETTINGS, platform: 'splunk', splunk: { ...DEFAULT_HUNT_SETTINGS.splunk, dns: 'index=dns' } });
    expect(loadHuntSettings()).toMatchObject({ platform: 'splunk', splunk: { dns: 'index=dns', web: DEFAULT_HUNT_SETTINGS.splunk.web } });
    localStorage.setItem('soc-toolbox-hunt-settings', JSON.stringify({ platform: 'elastic', lookback: '1y', splunk: { dns: 42 } }));
    expect(loadHuntSettings()).toEqual(DEFAULT_HUNT_SETTINGS);
  });
});
