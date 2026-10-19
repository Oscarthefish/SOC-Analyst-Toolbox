import type { Tool } from '../types/tool';
import { STORAGE_KEYS, readList, writeJson, isString } from './storage';

// Relative: the Vite dev/preview server proxies /api to the local backend
const BACKEND_URL = '';

export async function fetchCustomTools(): Promise<Tool[]> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/tools/custom`);
    if (!res.ok) return [];
    return (await res.json()) as Tool[];
  } catch {
    return [];
  }
}

export async function saveCustomTools(tools: Tool[]): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/tools/custom`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tools),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export function loadHiddenToolIds(): Set<string> {
  return new Set(readList(STORAGE_KEYS.hiddenTools, isString));
}

export function toggleHiddenToolId(id: string, currentIds: Set<string>): Set<string> {
  const next = new Set(currentIds);
  if (next.has(id)) next.delete(id); else next.add(id);
  writeJson(STORAGE_KEYS.hiddenTools, [...next]);
  return next;
}
