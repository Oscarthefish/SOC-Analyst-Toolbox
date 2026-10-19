/** Recently entered indicators, most recent first (shown in the input's Recent menu and the command palette). */

const KEY = 'soc-toolbox-ioc-history';
const MAX = 10;

export function loadRecentIndicators(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch { return []; }
}

export function addRecentIndicator(value: string): void {
  const trimmed = value.trim();
  if (!trimmed) return;
  const next = [trimmed, ...loadRecentIndicators().filter(h => h !== trimmed)].slice(0, MAX);
  try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
}

export function clearRecentIndicators(): void {
  try { localStorage.removeItem(KEY); } catch { /* storage unavailable */ }
}
