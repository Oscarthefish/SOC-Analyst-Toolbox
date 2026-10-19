import { TACTICS, TACTIC_BY_ID, attackUrl } from '../data/attack';
import type { TechniqueHit, EvidenceKind } from '../lib/attackMapping';

/**
 * ATT&CK techniques linked to the indicator, grouped by tactic in kill-chain order.
 * The chip style says how strong the link is: solid = a provider reported it,
 * outlined = inferred from a provider label, dashed = from the chosen workflow.
 */

export const PHASE_STYLE: Record<string, { bar: string; solid: string; soft: string; text: string }> = {
  c1: { bar: 'bg-c1', solid: 'bg-c1 text-on-ramp border-c1', soft: 'bg-c1-bg border-c1/40', text: 'text-c1-fg' },
  c2: { bar: 'bg-c2', solid: 'bg-c2 text-on-ramp border-c2', soft: 'bg-c2-bg border-c2/40', text: 'text-c2-fg' },
  c3: { bar: 'bg-c3', solid: 'bg-c3 text-on-ramp border-c3', soft: 'bg-c3-bg border-c3/40', text: 'text-c3-fg' },
  c4: { bar: 'bg-c4', solid: 'bg-c4 text-on-ramp border-c4', soft: 'bg-c4-bg border-c4/40', text: 'text-c4-fg' },
  c5: { bar: 'bg-c5', solid: 'bg-c5 text-on-ramp border-c5', soft: 'bg-c5-bg border-c5/40', text: 'text-c5-fg' },
  none: { bar: 'bg-line-strong', solid: 'bg-fg-3 text-surface border-fg-3', soft: 'bg-raised border-line', text: 'text-fg-2' },
};

export const EVIDENCE_LABEL: Record<EvidenceKind, string> = {
  reported: 'Reported by a provider',
  inferred: 'Inferred from a provider label',
  context: 'From the chosen workflow',
};

export function strongestEvidence(hit: TechniqueHit): EvidenceKind {
  return hit.evidence.some(e => e.kind === 'reported') ? 'reported' : hit.evidence.some(e => e.kind === 'inferred') ? 'inferred' : 'context';
}

function describe(hit: TechniqueHit): string {
  return hit.evidence.map(e => `${EVIDENCE_LABEL[e.kind]}: ${e.source}${e.detail ? ` (“${e.detail}”)` : ''}`).join('\n');
}

export function TechniqueChip({ hit }: { hit: TechniqueHit }) {
  const phase = TACTIC_BY_ID.get(hit.tactic)?.phase ?? 'none';
  const s = PHASE_STYLE[phase]!;
  const kind = strongestEvidence(hit);
  return (
    <a
      href={attackUrl(hit.id)}
      target="_blank"
      rel="noopener noreferrer"
      title={`${hit.id} ${hit.name}\n${describe(hit)}\nOpens attack.mitre.org`}
      className={`group inline-flex items-center gap-1.5 max-w-full h-6 pl-1.5 pr-2 rounded-md border text-[11px] transition-shadow hover:shadow-sm ${
        kind === 'reported' ? s.solid : kind === 'inferred' ? `${s.soft} ${s.text}` : `bg-surface border-dashed border-line-strong text-fg-2`
      }`}
    >
      <span className="font-mono font-semibold shrink-0">{hit.id}</span>
      <span className="truncate">{hit.name}</span>
    </a>
  );
}

export function EvidenceLegend() {
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-fg-3">
      <li className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-fg-3" aria-hidden />Reported</li>
      <li className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-raised border border-fg-4" aria-hidden />Inferred from a label</li>
      <li className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm border border-dashed border-line-strong" aria-hidden />Workflow context</li>
    </ul>
  );
}

interface Props {
  hits: TechniqueHit[];
  onHunt?: (techniqueIds: string[]) => void;
}

export function AttackPanel({ hits, onHunt }: Props) {
  const byTactic = TACTICS
    .map(t => ({ tactic: t, items: hits.filter(h => h.tactic === t.id) }))
    .filter(x => x.items.length > 0);
  const unknown = hits.filter(h => !h.tactic);
  const reported = hits.filter(h => strongestEvidence(h) === 'reported').length;
  const inferred = hits.filter(h => strongestEvidence(h) === 'inferred').length;

  return (
    <section className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <h2 className="wb-label">ATT&amp;CK techniques</h2>
        <EvidenceLegend />
      </div>

      <div className="rounded-lg border border-line-soft bg-inset p-3 space-y-3">
        {hits.length === 0 ? (
          <p className="text-xs text-fg-3">
            No provider linked this indicator to ATT&amp;CK techniques. Choose a workflow above for likely techniques, or pick them yourself on the Hunt page.
          </p>
        ) : (
          <>
            <p className="text-xs text-fg-3">
              {hits.length} technique{hits.length === 1 ? '' : 's'}: {reported} reported, {inferred} inferred from provider labels, {hits.length - reported - inferred} from workflow context.
              Hover a technique for its evidence.
            </p>
            <div className="grid gap-x-4 gap-y-3 grid-cols-[repeat(auto-fill,minmax(220px,1fr))]">
              {byTactic.map(({ tactic, items }) => (
                <div key={tactic.id} className="min-w-0">
                  <p className="flex items-center gap-1.5 mb-1.5 text-[11px] font-medium text-fg-2">
                    <span className={`w-1 h-3.5 rounded-full ${PHASE_STYLE[tactic.phase]!.bar}`} aria-hidden />
                    {tactic.name}
                  </p>
                  <div className="flex flex-col items-start gap-1">
                    {items.map(h => <TechniqueChip key={h.id} hit={h} />)}
                  </div>
                </div>
              ))}
              {unknown.length > 0 && (
                <div className="min-w-0">
                  <p className="mb-1.5 text-[11px] font-medium text-fg-2">Other</p>
                  <div className="flex flex-col items-start gap-1">{unknown.map(h => <TechniqueChip key={h.id} hit={h} />)}</div>
                </div>
              )}
            </div>
          </>
        )}
        {onHunt && (
          <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-line-soft">
            <button
              onClick={() => onHunt(hits.map(h => h.id))}
              className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md bg-accent text-white text-xs font-semibold hover:bg-accent-strong"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><circle cx="12" cy="12" r="8" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></svg>
              Build hunt queries
            </button>
            <span className="text-[11px] text-fg-4">KQL for Sentinel or Defender XDR, or SPL for Splunk, with this indicator and these techniques filled in.</span>
          </div>
        )}
      </div>
    </section>
  );
}
