/** Recently entered indicators, most recent first (shown in the input's Recent menu and the command palette). */
import { STORAGE_KEYS, readList, writeJson, removeKey, isString } from './storage';

const MAX = 10;

export function loadRecentIndicators(): string[] {
  return readList(STORAGE_KEYS.recentIndicators, isString);
}

export function addRecentIndicator(value: string): void {
  const trimmed = value.trim();
  if (!trimmed) return;
  writeJson(STORAGE_KEYS.recentIndicators, [trimmed, ...loadRecentIndicators().filter(h => h !== trimmed)].slice(0, MAX));
}

export function clearRecentIndicators(): void {
  removeKey(STORAGE_KEYS.recentIndicators);
}
