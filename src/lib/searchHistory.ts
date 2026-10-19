import type { AnalysisResponse } from '../types/analysis';
import type { IocInput } from '../types/enrichment';
import { STORAGE_KEYS, readList, writeJson, removeKey, hasStringFields, isRecord } from './storage';

const MAX_ENTRIES = 10;

export interface HistoryEntry {
  id: string;
  savedAt: string;
  ioc: IocInput;
  workflowId: string | null;
  result: AnalysisResponse;
}

function isHistoryEntry(x: unknown): x is HistoryEntry {
  return hasStringFields(x, ['id', 'savedAt'])
    && hasStringFields(x.ioc, ['normalised', 'type'])
    && isRecord(x.result) && isRecord(x.result.overall) && Array.isArray(x.result.results);
}

export function loadHistory(): HistoryEntry[] {
  return readList(STORAGE_KEYS.history, isHistoryEntry);
}

function persist(entries: HistoryEntry[]): HistoryEntry[] {
  if (writeJson(STORAGE_KEYS.history, entries)) return entries;
  // Storage quota: keep the newest half
  const trimmed = entries.slice(0, Math.max(1, Math.floor(entries.length / 2)));
  writeJson(STORAGE_KEYS.history, trimmed);
  return trimmed;
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
  removeKey(STORAGE_KEYS.history);
  return [];
}
