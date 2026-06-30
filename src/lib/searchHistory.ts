import type { AnalysisResponse } from '../types/analysis';
import type { IocInput } from '../types/enrichment';

const STORAGE_KEY = 'soc-toolbox-search-history';
const MAX_ENTRIES = 10;

export interface HistoryEntry {
  id: string;
  savedAt: string;
  ioc: IocInput;
  workflowId: string | null;
  result: AnalysisResponse;
}

export function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

function persist(entries: HistoryEntry[]): HistoryEntry[] {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Storage quota — drop oldest until it fits
    const trimmed = entries.slice(0, Math.max(1, Math.floor(entries.length / 2)));
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed)); } catch { /* give up */ }
    return trimmed;
  }
  return entries;
}

export function saveSearch(
  ioc: IocInput,
  workflowId: string | null,
  result: AnalysisResponse,
): HistoryEntry[] {
  const entry: HistoryEntry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    savedAt: new Date().toISOString(),
    ioc,
    workflowId,
    result,
  };
  const existing = loadHistory();
  // Replace any existing entry for the same normalised IOC + workflow combo
  const filtered = existing.filter(
    e => !(e.ioc.normalised === ioc.normalised && e.workflowId === workflowId),
  );
  return persist([entry, ...filtered].slice(0, MAX_ENTRIES));
}

export function removeEntry(id: string): HistoryEntry[] {
  return persist(loadHistory().filter(e => e.id !== id));
}

export function clearHistory(): HistoryEntry[] {
  try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  return [];
}
