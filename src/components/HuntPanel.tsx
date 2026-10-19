import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { TACTICS, TECHNIQUES, TECHNIQUE_BY_ID, attackUrl } from '../data/attack';
import { SPLUNK_SOURCE_LABEL, DEFAULT_SPLUNK_SOURCES } from '../data/huntQueries';
import type { Platform, SplunkSource, IocKind } from '../data/huntQueries';
import { parseBatchInput } from '../lib/batch';
import { groupIndicators, buildHunts, huntableTechniques } from '../lib/hunting';
import type { BuiltHunt, HuntSettings, Lookback, IndicatorGroup } from '../lib/hunting';
import { loadHuntSettings, saveHuntSettings } from '../lib/huntSettings';
import type { TechniqueHit } from '../lib/attackMapping';
import { CopyButton } from './CopyButton';
import { IocTypeChip } from './IocTypeChip';
import { PHASE_STYLE, EvidenceLegend, EVIDENCE_LABEL, TechniqueChip } from './AttackPanel';

/**
 * Hunt query builder: indicators and ATT&CK techniques in, KQL or SPL out.
 * Indicator sweeps look for the indicators themselves; technique hunts look for
 * the behaviour whether or not these indicators are involved.
 */

const PLATFORMS: { id: Platform; label: string; sub: string }[] = [
  { id: 'sentinel', label: 'Sentinel', sub: 'KQL · TimeGenerated' },
  { id: 'defender', label: 'Defender XDR', sub: 'KQL · Advanced hunting' },
  { id: 'splunk', label: 'Splunk', sub: 'SPL · CIM fields' },
];
const LOOKBACKS: Lookback[] = ['24h', '7d', '30d', '90d'];

const KIND_LABEL: Record<IocKind, string> = { ip: 'IP addresses', domain: 'Domains', url: 'URLs', hash: 'File hashes', email: 'Email addresses' };
const KIND_CHIP: Record<IocKind, string> = { ip: 'ipv4', domain: 'domain', url: 'url', hash: 'sha256', email: 'email' };

// ── Query code block with light highlighting ───────────────────────────────

const KEYWORDS = /^(\s*\|\s*)([a-zA-Z-]+)/;

function highlight(line: string, i: number): ReactNode {
  const parts: ReactNode[] = [];
  let rest = line;
  const m = KEYWORDS.exec(rest);
  if (m) {
    parts.push(<span key="p" className="text-fg-4">{m[1]}</span>, <span key="k" className="text-c1-fg font-semibold">{m[2]}</span>);
    rest = rest.slice(m[0].length);
  } else if (/^let\s/.test(rest)) {
    parts.push(<span key="l" className="text-c3-fg font-semibold">let</span>);
    rest = rest.slice(3);
  }
  // Quoted strings stand out so the analyst can see what was filled in
  rest.split(/("(?:[^"\\]|\\.)*")/g).forEach((chunk, j) => {
    parts.push(chunk.startsWith('"') ? <span key={j} className="text-c4-fg">{chunk}</span> : <span key={j}>{chunk}</span>);
  });
  return <span key={i} className="block">{parts}{'\n'}</span>;
}

function QueryCard({ hunt }: { hunt: BuiltHunt }) {
  const t = hunt.template;
  return (
    <article className="wb-card overflow-hidden">
      <header className="flex flex-wrap items-start justify-between gap-2 px-4 pt-3 pb-2">
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold text-fg-1">{t.title}</h3>
          <p className="mt-0.5 text-[11px] text-fg-3">{t.source}</p>
        </div>
        <CopyButton text={hunt.query} label="query" />
      </header>
      <div className="px-4 pb-2 flex flex-wrap gap-1">
        {t.techniques.map(id => {
          const tech = TECHNIQUE_BY_ID.get(id);
          const phase = TACTICS.find(x => x.id === tech?.tactics[0])?.phase ?? 'none';
          const on = hunt.matched.some(m => m.split('.')[0] === id.split('.')[0]);
          return (
            <a key={id} href={attackUrl(id)} target="_blank" rel="noopener noreferrer" title={tech?.name}
              className={`inline-flex items-center h-5 px-1.5 rounded border font-mono text-[10px] font-semibold ${on ? PHASE_STYLE[phase]!.solid : `${PHASE_STYLE[phase]!.soft} ${PHASE_STYLE[phase]!.text}`}`}>
              {id}
            </a>
          );
        })}
      </div>
      <pre tabIndex={0} aria-label={`${t.title} query`} className="mx-4 mb-3 max-h-80 overflow-auto focus-visible:outline-2 focus-visible:outline-accent rounded-md border border-line bg-inset px-3 py-2.5 text-[12px] leading-[1.55] font-mono text-fg-1">
        <code>{hunt.query.split('\n').map(highlight)}</code>
      </pre>
      <p className="px-4 pb-3 text-xs text-fg-2 leading-relaxed">
        <span className="font-medium text-fg-1">Look for: </span>{t.lookFor}
      </p>
    </article>
  );
}

// ── Technique picker (ATT&CK matrix of what we can hunt) ───────────────────

function TechniqueMatrix({ platform, selected, suggested, onToggle }: {
  platform: Platform; selected: string[]; suggested: TechniqueHit[]; onToggle: (id: string) => void;
}) {
  const [filter, setFilter] = useState('');
  const huntable = useMemo(() => huntableTechniques(platform), [platform]);
  const suggestedById = new Map(suggested.map(s => [s.id, s]));
  const f = filter.trim().toLowerCase();

  const columns = TACTICS.map(tactic => ({
    tactic,
    items: TECHNIQUES.filter(t => t.tactics[0] === tactic.id)
      .filter(t => huntable.has(t.id) || selected.includes(t.id) || suggestedById.has(t.id))
      .filter(t => !f || t.id.toLowerCase().includes(f) || t.name.toLowerCase().includes(f)),
  })).filter(c => c.items.length > 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter techniques (e.g. T1110, phishing)"
          aria-label="Filter techniques"
          className="h-8 w-64 max-w-full px-2.5 rounded-md border border-line-strong bg-surface text-[13px] focus:outline-none focus:border-accent"
        />
        <ul className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-fg-3">
          <li>Filled = selected (colour shows the kill-chain phase)</li>
          <li className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-accent" aria-hidden />Linked to the current investigation</li>
          <li className="flex items-center gap-1.5"><span className="text-fg-4">No hunt</span> = no built-in query on this platform yet</li>
        </ul>
      </div>
      <div className="overflow-x-auto pb-1">
        <div className="grid gap-2 min-w-max" style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(168px, 1fr))` }}>
          {columns.map(({ tactic, items }) => {
            const s = PHASE_STYLE[tactic.phase]!;
            return (
              <div key={tactic.id} className="min-w-0">
                <div className={`h-1 rounded-full ${s.bar}`} aria-hidden />
                <p className="mt-1.5 mb-1.5 text-[11px] font-semibold text-fg-1 leading-tight">{tactic.name}</p>
                <div className="flex flex-col gap-1">
                  {items.map(t => {
                    const on = selected.includes(t.id);
                    const sug = suggestedById.get(t.id);
                    const can = huntable.has(t.id);
                    return (
                      <button
                        key={t.id}
                        onClick={() => onToggle(t.id)}
                        aria-pressed={on}
                        title={sug ? `${t.name}\n${sug.evidence.map(e => `${EVIDENCE_LABEL[e.kind]}: ${e.source}${e.detail ? ` (“${e.detail}”)` : ''}`).join('\n')}` : t.name}
                        className={`relative text-left rounded-md border px-2 py-1 text-[11px] leading-snug transition-colors ${
                          on ? s.solid : `bg-surface border-line hover:border-line-strong ${can ? 'text-fg-1' : 'text-fg-4'}`
                        }`}
                      >
                        {sug && <span className={`absolute top-1 right-1 w-1.5 h-1.5 rounded-full ${on ? 'bg-on-ramp' : 'bg-accent'}`} aria-label="Linked to the current investigation" />}
                        <span className="block font-mono font-semibold text-[10px]">{t.id}</span>
                        <span className="block pr-2">{t.name}</span>
                        {!can && <span className="block text-[10px]">No hunt</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

interface Props {
  indicators: string;
  onIndicatorsChange: (v: string) => void;
  techniques: string[];
  onTechniquesChange: (ids: string[]) => void;
  /** Techniques linked to the indicator currently open on Investigate */
  suggested: TechniqueHit[];
  currentIndicator?: string;
}

function groupLabel(g: IndicatorGroup) {
  return g.kind === 'hash' ? `${g.hashType?.toUpperCase()} hashes` : KIND_LABEL[g.kind];
}

export function HuntPanel({ indicators, onIndicatorsChange, techniques, onTechniquesChange, suggested, currentIndicator }: Props) {
  const [settings, setSettings] = useState<HuntSettings>(() => loadHuntSettings());
  const [showSplunk, setShowSplunk] = useState(false);
  useEffect(() => { saveHuntSettings(settings); }, [settings]);

  const parsed = useMemo(() => parseBatchInput(indicators), [indicators]);
  const groups = useMemo(() => groupIndicators(parsed.rows.filter(r => r.status === 'pending')), [parsed]);
  const unsupported = parsed.rows.filter(r => r.status === 'pending' && !groups.some(g => g.values.includes(r.normalised)));
  const { sweeps, hunts } = useMemo(() => buildHunts(groups, techniques, settings), [groups, techniques, settings]);

  const toggle = (id: string) => onTechniquesChange(techniques.includes(id) ? techniques.filter(x => x !== id) : [...techniques, id]);
  const suggestedIds = suggested.map(s => s.id);
  const missingSuggestions = suggestedIds.filter(id => !techniques.includes(id));

  return (
    <div className="space-y-4">
      {/* ── Inputs ─────────────────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <section className="wb-card p-4 space-y-2.5">
          <div className="flex items-baseline justify-between gap-3">
            <label htmlFor="hunt-indicators" className="wb-label">Indicators</label>
            <div className="flex items-center gap-3">
              {currentIndicator && !indicators.includes(currentIndicator) && (
                <button onClick={() => onIndicatorsChange(indicators ? `${indicators.trimEnd()}\n${currentIndicator}` : currentIndicator)} className="text-[11px] text-accent-fg hover:underline">
                  Add current indicator
                </button>
              )}
              <span className="text-[11px] text-fg-4">One per line · defanged is fine · optional</span>
            </div>
          </div>
          <textarea
            id="hunt-indicators"
            value={indicators}
            onChange={e => onIndicatorsChange(e.target.value)}
            rows={4}
            spellCheck={false}
            placeholder={'185.220.101.4\nlogin-micros0ft[.]com\n44d88612fea8a8f36de82e1278abb02f'}
            className="w-full px-3 py-2 text-[13px] font-mono rounded-md border border-line-strong bg-surface text-fg-1 resize-y focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent/15"
          />
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-fg-3">
            {groups.map(g => (
              <span key={g.kind + (g.hashType ?? '')} className="inline-flex items-center gap-1.5 h-6 px-2 rounded-md border border-line bg-inset">
                <IocTypeChip type={g.hashType ?? KIND_CHIP[g.kind]} size="sm" />
                {g.values.length} {groupLabel(g).toLowerCase()}
              </span>
            ))}
            {unsupported.length > 0 && <span className="text-fg-4">{unsupported.length} not searchable here (CVE, ASN, CIDR)</span>}
            {groups.length === 0 && <span className="text-fg-4">No indicators — only technique hunts will be built.</span>}
          </div>
        </section>

        <section className="wb-card p-4 space-y-3">
          <div>
            <p className="wb-label mb-1.5">Platform</p>
            <div className="grid grid-cols-3 gap-1" role="radiogroup" aria-label="Query platform">
              {PLATFORMS.map(p => (
                <button
                  key={p.id}
                  role="radio"
                  aria-checked={settings.platform === p.id}
                  onClick={() => setSettings(s => ({ ...s, platform: p.id }))}
                  className={`rounded-md border px-2 py-1.5 text-left transition-colors ${
                    settings.platform === p.id ? 'bg-selected border-selected text-selected-fg' : 'bg-surface border-line text-fg-2 hover:border-line-strong'
                  }`}
                >
                  <span className="block text-xs font-semibold">{p.label}</span>
                  <span className="block text-[10px] opacity-80">{p.sub}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="wb-label mb-1.5">Look back</p>
            <div className="flex gap-1" role="radiogroup" aria-label="Look back">
              {LOOKBACKS.map(l => (
                <button key={l} role="radio" aria-checked={settings.lookback === l} onClick={() => setSettings(s => ({ ...s, lookback: l }))}
                  className={`h-7 px-2.5 rounded-md border text-xs font-medium ${settings.lookback === l ? 'bg-selected border-selected text-selected-fg' : 'bg-surface border-line text-fg-2 hover:border-line-strong'}`}>
                  {l}
                </button>
              ))}
            </div>
          </div>
          {settings.platform === 'splunk' && (
            <div className="pt-1 border-t border-line-soft">
              <button onClick={() => setShowSplunk(v => !v)} aria-expanded={showSplunk} className="text-[11px] text-accent-fg hover:underline">
                {showSplunk ? 'Hide' : 'Edit'} Splunk base searches
              </button>
              {showSplunk && (
                <div className="mt-2 space-y-1.5">
                  <p className="text-[11px] text-fg-3">Defaults use CIM tags. Replace them with your index and sourcetype to make searches faster.</p>
                  {(Object.keys(SPLUNK_SOURCE_LABEL) as SplunkSource[]).map(k => (
                    <label key={k} className="block">
                      <span className="text-[11px] text-fg-2">{SPLUNK_SOURCE_LABEL[k]}</span>
                      <input
                        value={settings.splunk[k]}
                        onChange={e => setSettings(s => ({ ...s, splunk: { ...s.splunk, [k]: e.target.value } }))}
                        className="mt-0.5 w-full h-7 px-2 rounded border border-line-strong bg-surface text-[11px] font-mono focus:outline-none focus:border-accent"
                      />
                    </label>
                  ))}
                  <button onClick={() => setSettings(s => ({ ...s, splunk: { ...DEFAULT_SPLUNK_SOURCES } }))} className="text-[11px] text-fg-3 hover:text-fg-1">Reset to CIM defaults</button>
                </div>
              )}
            </div>
          )}
        </section>
      </div>

      {/* ── Techniques ─────────────────────────────────────────────── */}
      <section className="wb-card p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="wb-label">ATT&amp;CK techniques to hunt</h2>
            <p className="text-[11px] text-fg-4 mt-0.5">{techniques.length} selected · techniques with built-in hunts for {PLATFORMS.find(p => p.id === settings.platform)!.label}</p>
          </div>
          <div className="flex items-center gap-2">
            {missingSuggestions.length > 0 && (
              <button onClick={() => onTechniquesChange([...techniques, ...missingSuggestions])} className="h-7 px-2.5 rounded-md border border-accent-line bg-accent-bg text-accent-fg text-xs font-medium">
                Add {missingSuggestions.length} from investigation
              </button>
            )}
            {techniques.length > 0 && (
              <button onClick={() => onTechniquesChange([])} className="h-7 px-2.5 rounded-md text-xs text-fg-3 hover:text-fg-1">Clear</button>
            )}
          </div>
        </div>
        {suggested.length > 0 && (
          <div className="rounded-md bg-inset border border-line-soft px-3 py-2 space-y-1.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] text-fg-2">Linked to <span className="font-mono text-fg-1">{currentIndicator}</span></p>
              <EvidenceLegend />
            </div>
            <div className="flex flex-wrap gap-1">{suggested.map(s => <TechniqueChip key={s.id} hit={s} />)}</div>
          </div>
        )}
        <TechniqueMatrix platform={settings.platform} selected={techniques} suggested={suggested} onToggle={toggle} />
      </section>

      {/* ── Output ─────────────────────────────────────────────────── */}
      {sweeps.length === 0 && hunts.length === 0 ? (
        <div className="wb-card px-6 py-8 text-center">
          <p className="text-[13px] font-medium text-fg-1">Add indicators or pick techniques</p>
          <p className="text-xs text-fg-3 mt-1 max-w-md mx-auto">
            Indicators give you sweeps (where has this appeared?). Techniques give you hunts (is this behaviour happening anywhere?).
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {sweeps.length > 0 && (
            <section className="space-y-2">
              <h2 className="wb-label">Indicator sweeps · {sweeps.length}</h2>
              {groups.map(g => {
                const items = sweeps.filter(s => s.group === g);
                if (items.length === 0) return null;
                return (
                  <div key={g.kind + (g.hashType ?? '')} className="space-y-2">
                    <p className="flex items-center gap-2 text-xs text-fg-2"><IocTypeChip type={g.hashType ?? KIND_CHIP[g.kind]} size="sm" />{groupLabel(g)} ({g.values.length})</p>
                    <div className="grid gap-3">{items.map(h => <QueryCard key={h.key} hunt={h} />)}</div>
                  </div>
                );
              })}
            </section>
          )}
          {hunts.length > 0 && (
            <section className="space-y-2">
              <h2 className="wb-label">Technique hunts · {hunts.length}</h2>
              <div className="grid gap-3">{hunts.map(h => <QueryCard key={h.key} hunt={h} />)}</div>
            </section>
          )}
          {techniques.some(id => !hunts.some(h => h.matched.includes(id))) && (
            <p className="text-xs text-fg-4">
              No built-in {PLATFORMS.find(p => p.id === settings.platform)!.label} hunt yet for {techniques.filter(id => !hunts.some(h => h.matched.includes(id))).join(', ')}. Each technique links to attack.mitre.org for detection guidance.
            </p>
          )}
        </div>
      )}

      <p className="text-[11px] text-fg-4">
        Queries are templates: check table and field names against your environment and tune thresholds before scheduling them as detections. Nothing is run from here.
      </p>
    </div>
  );
}
