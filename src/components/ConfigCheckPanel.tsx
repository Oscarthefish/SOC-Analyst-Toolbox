import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { Tool } from '../types/tool';
import { buildTemplateVars, applyTemplate, safeHref } from '../lib/template';
import { detectIoc } from '../lib/detectIoc';
import { IocTypeChip, iocTypeDot } from './IocTypeChip';
import { ToolCategoryBadge } from './ToolCategoryBadge';

interface ConfigCheckPanelProps {
  tools: Tool[];
  customToolCount: number;
}

const SAMPLE_IOCS = [
  { label: 'IPv4',   value: '8.8.8.8' },
  { label: 'Domain', value: 'example.com' },
  { label: 'URL',    value: 'https://login.example.com/reset?token=abc' },
  { label: 'SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { label: 'Email',  value: 'user@example.com' },
  { label: 'ASN',    value: 'AS15169' },
  { label: 'CIDR',   value: '192.168.1.0/24' },
];

type UrlStatus = 'ok' | 'home' | 'broken' | 'na';

function checkUrl(template: string, renderedUrl: string): UrlStatus {
  if (/\{\{[^}]+\}\}/.test(renderedUrl)) return 'broken';
  if (!renderedUrl.startsWith('http')) return 'broken';
  if (renderedUrl === template && template.includes('{{')) return 'home';
  if (!template.includes('{{')) return 'home';
  return 'ok';
}

const STATUS: Record<Exclude<UrlStatus, 'na'>, { pill: string; label: string; icon: ReactNode }> = {
  ok: {
    pill: 'bg-ok-bg text-ok-fg border-ok-line', label: 'Renders',
    icon: <path d="M5 12l5 5 9-10" />,
  },
  home: {
    pill: 'bg-warn-bg text-warn-fg border-warn-line', label: 'Home URL',
    icon: <path d="M6 12h12" />,
  },
  broken: {
    pill: 'bg-danger-bg text-danger-fg border-danger-line', label: 'Broken',
    icon: <path d="M7 7l10 10M17 7L7 17" />,
  },
};

function StatusMark({ status }: { status: Exclude<UrlStatus, 'na'> }) {
  return (
    <span className={`inline-grid place-items-center w-5 h-5 rounded-full border ${STATUS[status].pill}`}>
      <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round">{STATUS[status].icon}</svg>
    </span>
  );
}

export function ConfigCheckPanel({ tools, customToolCount }: ConfigCheckPanelProps) {
  const [problemsOnly, setProblemsOnly] = useState(false);

  const samples = useMemo(() => SAMPLE_IOCS.map(s => ({ ...s, detected: detectIoc(s.value) })), []);

  // Render every template once against every applicable sample
  const rows = useMemo(() => tools.map(tool => ({
    tool,
    cells: samples.map(s => {
      if (!tool.inputTypes.includes(s.detected.type)) return { status: 'na' as UrlStatus, rendered: '' };
      const rendered = applyTemplate(tool.urlTemplate, buildTemplateVars(s.detected));
      return { status: checkUrl(tool.urlTemplate, rendered), rendered };
    }),
  })), [tools, samples]);

  const totals = useMemo(() => {
    const t = { ok: 0, home: 0, broken: 0 };
    for (const r of rows) for (const c of r.cells) if (c.status !== 'na') t[c.status] += 1;
    return t;
  }, [rows]);

  const perType = samples.map((s, i) => ({
    sample: s,
    ok: rows.filter(r => r.cells[i]!.status === 'ok').length,
    any: rows.filter(r => r.cells[i]!.status !== 'na').length,
  }));
  const maxPerType = Math.max(1, ...perType.map(p => p.any));

  const visible = problemsOnly ? rows.filter(r => r.cells.some(c => c.status === 'broken' || c.status === 'home')) : rows;

  return (
    <div className="space-y-4">
      {/* ── Overview ──────────────────────────────────────────────────── */}
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="grid gap-3 grid-cols-3">
          {(Object.keys(STATUS) as (keyof typeof STATUS)[]).map(k => (
            <div key={k} className="wb-card p-4">
              <span className={`inline-grid place-items-center w-8 h-8 rounded-full border ${STATUS[k].pill}`} aria-hidden>
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.6} strokeLinecap="round" strokeLinejoin="round">{STATUS[k].icon}</svg>
              </span>
              <p className="mt-2 text-[22px] leading-none font-semibold text-fg-1 tabular-nums">{totals[k]}</p>
              <p className="mt-1 text-xs text-fg-3">{STATUS[k].label}</p>
            </div>
          ))}
        </div>

        <section className="wb-card p-4">
          <div className="flex items-baseline justify-between gap-2 mb-2.5">
            <h2 className="wb-label">Working links per indicator type</h2>
            <span className="text-[11px] text-fg-4">{tools.length - customToolCount} built-in · {customToolCount} custom</span>
          </div>
          <ul className="space-y-1.5">
            {perType.map(p => (
              <li key={p.sample.label} className="grid grid-cols-[4.5rem_1fr_3.5rem] items-center gap-2 text-[11px]">
                <span className="text-fg-2">{p.sample.label}</span>
                <span className="relative h-2 rounded-full bg-raised overflow-hidden" title={`${p.ok} render, ${p.any - p.ok} home or broken`}>
                  <span className="absolute inset-y-0 left-0 rounded-full bg-line-strong" style={{ width: `${(p.any / maxPerType) * 100}%` }} />
                  <span className={`absolute inset-y-0 left-0 rounded-full ${iocTypeDot(p.sample.detected.type)}`} style={{ width: `${(p.ok / maxPerType) * 100}%` }} />
                </span>
                <span className="text-right tabular-nums text-fg-1 font-medium">{p.ok}<span className="text-fg-4">/{p.any}</span></span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {customToolCount === 0 && (
        <p className="text-xs text-fg-3">
          No custom tools yet. Add internal tools (SIEM, EDR, ticketing) from the <strong className="font-medium text-fg-2">Tool library</strong> page; they are saved to <code className="font-mono text-[11px]">backend/data/customTools.json</code>.
        </p>
      )}

      {/* ── Matrix ────────────────────────────────────────────────────── */}
      <div className="wb-card overflow-hidden">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 border-b border-line text-xs text-fg-3">
          {(Object.keys(STATUS) as (keyof typeof STATUS)[]).map(k => (
            <span key={k} className="flex items-center gap-1.5"><StatusMark status={k} />{k === 'home' ? 'Home URL / manual lookup' : k === 'broken' ? 'Template produces a broken URL' : 'URL renders correctly'}</span>
          ))}
          <span className="flex items-center gap-1.5"><span className="w-5 text-center text-fg-4">·</span>Type not supported</span>
          <label className="ml-auto flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" checked={problemsOnly} onChange={e => setProblemsOnly(e.target.checked)} className="accent-[var(--color-accent)]" />
            Only tools with a home or broken link
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-line bg-inset">
                <th className="text-left py-2.5 px-4 wb-label">Tool</th>
                <th className="text-left py-2.5 px-3 wb-label hidden sm:table-cell">Category</th>
                {samples.map(s => (
                  <th key={s.label} className="text-center py-2 px-2 min-w-[60px]">
                    <IocTypeChip type={s.detected.type} size="sm" />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {visible.map(({ tool, cells }) => (
                <tr key={tool.id} className="hover:bg-inset transition-colors">
                  <td className="py-2 px-4">
                    <div className="flex items-center gap-1.5">
                      <span className="text-fg-1 font-medium">{tool.name}</span>
                      {tool.id.startsWith('custom-') && (
                        <span className="text-[10px] px-1.5 rounded bg-ok-bg border border-ok-line text-ok-fg font-medium">custom</span>
                      )}
                    </div>
                    <div className="text-fg-4 mt-0.5 truncate max-w-[240px] font-mono text-[11px]" title={tool.urlTemplate}>
                      {tool.urlTemplate.replace(/^https?:\/\//, '')}
                    </div>
                  </td>
                  <td className="py-2 px-3 hidden sm:table-cell"><ToolCategoryBadge category={tool.category} /></td>
                  {cells.map((c, i) => (
                    <td key={samples[i]!.label} className="py-2 px-2 text-center">
                      {c.status === 'na' ? (
                        <span className="text-fg-4" aria-label="Not supported">·</span>
                      ) : c.status === 'broken' ? (
                        <span title={`Broken: ${c.rendered}`} aria-label="Broken"><StatusMark status="broken" /></span>
                      ) : (
                        <a
                          href={safeHref(c.status === 'ok' ? c.rendered : tool.urlTemplate)}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={c.status === 'ok' ? c.rendered : 'Home/manual URL — no template variable applied'}
                          aria-label={`${tool.name} ${samples[i]!.label}: ${STATUS[c.status].label}`}
                          className="inline-block hover:scale-110 transition-transform"
                        >
                          <StatusMark status={c.status} />
                        </a>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
              {visible.length === 0 && (
                <tr><td colSpan={samples.length + 2} className="px-4 py-6 text-fg-4">Every template renders a working link.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-xs text-fg-4">
        Selecting a mark opens the tool in a new tab with the sample indicator. Nothing is sent automatically.
      </p>
    </div>
  );
}
