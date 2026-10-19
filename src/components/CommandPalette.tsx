import { useEffect, useMemo, useRef, useState } from 'react';
import type { Tab } from './AppShell';
import { ALL_NAV_ITEMS } from './AppShell';
import type { CaseRecord } from '../types/case';
import { detectIoc } from '../lib/detectIoc';
import { loadRecentIndicators } from '../lib/recentIndicators';
import { verdictLabel } from '../lib/cases';

interface Command {
  id: string;
  group: string;
  label: string;
  hint?: string;
  mono?: boolean;
  run: () => void;
}

interface Props {
  open: boolean;
  onClose: () => void;
  cases: CaseRecord[];
  onNavigate: (tab: Tab) => void;
  onInvestigate: (value: string) => void;
  onOpenCase: (c: CaseRecord) => void;
}

function matches(text: string, q: string): boolean {
  if (!q) return true;
  const t = text.toLowerCase();
  return q.toLowerCase().split(/\s+/).every(part => t.includes(part));
}

/** ⌘K / Ctrl+K: jump to a page, a recent indicator or an open case, or investigate what you type. */
export function CommandPalette({ open, onClose, cases, onNavigate, onInvestigate, onOpenCase }: Props) {
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Focus the search on open; return focus to where the user was on close
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    setQuery('');
    setIndex(0);
    requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      // Only restore if the chosen command didn't move focus somewhere deliberate
      requestAnimationFrame(() => {
        if (document.activeElement === document.body) previous?.focus?.();
      });
    };
  }, [open]);

  const commands = useMemo<Command[]>(() => {
    if (!open) return [];
    const q = query.trim();
    const out: Command[] = [];

    const detected = q ? detectIoc(q) : null;
    if (detected && (detected.type !== 'unknown' || detected.isEmailHeader)) {
      out.push({
        id: 'investigate',
        group: 'Indicator',
        label: `Investigate ${detected.normalised}`,
        hint: detected.type.toUpperCase(),
        mono: true,
        run: () => onInvestigate(q),
      });
    }


    for (const c of cases.filter(c => c.status === 'open')) {
      if (matches(`${c.title} ${c.ticketRef} ${c.ioc.normalised}`, q)) {
        out.push({
          id: `case:${c.id}`,
          group: 'Open cases',
          label: c.title,
          hint: [c.ticketRef, verdictLabel(c.verdict)].filter(Boolean).join(' · '),
          run: () => onOpenCase(c),
        });
      }
    }

    for (const v of loadRecentIndicators()) {
      if (matches(v, q) && !(detected && v === q)) {
        out.push({ id: `recent:${v}`, group: 'Recent indicators', label: v, mono: true, run: () => onInvestigate(v) });
      }
    }
    const pages: Command[] = ALL_NAV_ITEMS
      .filter(item => matches(`${item.label} ${item.title}`, q))
      .map(item => ({ id: `nav:${item.id}`, group: 'Go to', label: item.label, run: () => onNavigate(item.id) }));
    // With a query, page names are the likeliest target; without one, recent work is
    return q ? [...out.slice(0, detected ? 1 : 0), ...pages, ...out.slice(detected ? 1 : 0)] : [...out, ...pages];
  }, [open, query, cases, onInvestigate, onNavigate, onOpenCase]);

  useEffect(() => { setIndex(0); }, [query]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${index}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [index]);

  if (!open) return null;

  function choose(c: Command | undefined) {
    if (!c) return;
    onClose();
    c.run();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIndex(i => Math.min(i + 1, commands.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIndex(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(commands[index]); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  }

  let lastGroup = '';
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4" onMouseDown={onClose}>
      <div className="absolute inset-0 bg-black/30" aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onMouseDown={e => e.stopPropagation()}
        onKeyDown={onKeyDown}
        className="relative w-full max-w-[560px] bg-surface border border-line rounded-xl shadow-lg overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-4 border-b border-line">
          <svg className="w-4 h-4 text-fg-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Type an indicator, page or case…"
            role="combobox"
            aria-expanded="true"
            aria-controls="command-list"
            aria-activedescendant={commands[index] ? `cmd-${index}` : undefined}
            className="flex-1 h-12 bg-transparent text-[14px] text-fg-1 focus:outline-none"
            spellCheck={false}
            autoComplete="off"
          />
          <span className="kbd">esc</span>
        </div>
        <div ref={listRef} id="command-list" role="listbox" className="max-h-[50vh] overflow-y-auto py-1.5">
          {commands.length === 0 && <p className="px-4 py-6 text-xs text-fg-4">No matches.</p>}
          {commands.map((c, i) => {
            const header = c.group !== lastGroup ? c.group : null;
            lastGroup = c.group;
            return (
              <div key={c.id}>
                {header && <p className="px-4 pt-2 pb-1 text-[11px] text-fg-4">{header}</p>}
                <button
                  id={`cmd-${i}`}
                  data-index={i}
                  role="option"
                  aria-selected={i === index}
                  onMouseMove={() => setIndex(i)}
                  onClick={() => choose(c)}
                  className={`w-full flex items-center gap-3 px-4 h-9 text-left text-[13px] ${i === index ? 'bg-raised text-fg-1' : 'text-fg-2'}`}
                >
                  <span className={`flex-1 truncate ${c.mono ? 'font-mono text-[12px]' : ''}`}>{c.label}</span>
                  {c.hint && <span className="text-[11px] text-fg-4 shrink-0">{c.hint}</span>}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
