import { useMemo } from 'react';
import type { EnrichmentResult } from '../types/enrichment';
import { buildRelationships, RELATION_LABEL } from '../lib/relationships';
import type { RelationKind, RelationNode } from '../lib/relationships';

/**
 * Hub-and-spoke view of what the indicator connects to. Infrastructure context sits
 * on the left, related hosts and threat labels on the right. Line weight is the
 * number of providers that agree; host and ASN nodes pivot into a new investigation.
 */

const KIND_STYLE: Record<RelationKind, { pill: string; text: string; edge: string; badge: string; dot: string }> = {
  network:      { pill: 'fill-c1-bg stroke-c1', text: 'fill-c1-fg', edge: 'stroke-c1', badge: 'fill-c1', dot: 'bg-c1' },
  host:         { pill: 'fill-c2-bg stroke-c2', text: 'fill-c2-fg', edge: 'stroke-c2', badge: 'fill-c2', dot: 'bg-c2' },
  registration: { pill: 'fill-c5-bg stroke-c5', text: 'fill-c5-fg', edge: 'stroke-c5', badge: 'fill-c5', dot: 'bg-c5' },
  exposure:     { pill: 'fill-c3-bg stroke-c3', text: 'fill-c3-fg', edge: 'stroke-c3', badge: 'fill-c3', dot: 'bg-c3' },
  threat:       { pill: 'fill-c4-bg stroke-c4', text: 'fill-c4-fg', edge: 'stroke-c4', badge: 'fill-c4', dot: 'bg-c4' },
};

const LEFT: RelationKind[] = ['network', 'registration', 'exposure'];
const RIGHT: RelationKind[] = ['host', 'threat'];

const W = 800;
const PILL_W = 196;
const PILL_H = 24;
const ROW = 30;
const HEAD = 22;
const CENTRE_W = 220;
const LEFT_X = 8;
const RIGHT_X = W - 8 - PILL_W;
const CENTRE_X = (W - CENTRE_W) / 2;

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

interface Placed { node: RelationNode; x: number; y: number }
interface Header { kind: RelationKind; x: number; y: number; count: number }

function layout(nodes: RelationNode[], kinds: RelationKind[], x: number) {
  const placed: Placed[] = [];
  const headers: Header[] = [];
  let y = 0;
  for (const kind of kinds) {
    const list = nodes.filter(n => n.kind === kind);
    if (list.length === 0) continue;
    headers.push({ kind, x, y: y + 14, count: list.length });
    y += HEAD;
    for (const node of list) { placed.push({ node, x, y }); y += ROW; }
    y += 6;
  }
  return { placed, headers, height: y };
}

interface Props {
  results: EnrichmentResult[];
  indicator: string;
  onPivot?: (value: string) => void;
}

export function RelationshipGraph({ results, indicator, onPivot }: Props) {
  const nodes = useMemo(() => buildRelationships(results, indicator), [results, indicator]);
  if (nodes.length === 0) return null;

  const left = layout(nodes, LEFT, LEFT_X);
  const right = layout(nodes, RIGHT, RIGHT_X);
  const H = Math.max(left.height, right.height, 60) + 8;
  const cy = H / 2;
  const kindsPresent = [...LEFT, ...RIGHT].filter(k => nodes.some(n => n.kind === k));

  const edge = (p: Placed, side: 'l' | 'r') => {
    const ny = p.y + PILL_H / 2;
    const x1 = side === 'l' ? p.x + PILL_W : p.x;
    const x2 = side === 'l' ? CENTRE_X : CENTRE_X + CENTRE_W;
    const mx = (x1 + x2) / 2;
    return `M${x1},${ny} C${mx},${ny} ${mx},${cy} ${x2},${cy}`;
  };

  const renderNode = (p: Placed, side: 'l' | 'r') => {
    const s = KIND_STYLE[p.node.kind];
    const pivot = onPivot && p.node.pivot;
    const n = p.node.sources.length;
    const badgeX = side === 'l' ? p.x + PILL_W - 14 : p.x + 14;
    const textX = side === 'l' ? p.x + 10 : p.x + 28;
    const title = `${p.node.role}: ${p.node.value}\nReported by ${p.node.sources.join(', ')}${pivot ? '\nClick to investigate' : ''}`;
    const body = (
      <>
        <title>{title}</title>
        <rect x={p.x} y={p.y} width={PILL_W} height={PILL_H} rx={PILL_H / 2} className={`${s.pill} ${pivot ? 'group-hover:stroke-2 group-focus-visible:stroke-2' : ''}`} strokeWidth={1} />
        <text x={textX} y={p.y + 16} className={`${s.text} font-mono`} fontSize={11}>{clip(p.node.value, side === 'l' ? 24 : 23)}</text>
        <circle cx={badgeX} cy={p.y + PILL_H / 2} r={8} className={s.badge} />
        <text x={badgeX} y={p.y + 16} textAnchor="middle" fontSize={10} fontWeight={600} className="fill-surface">{n}</text>
      </>
    );
    return pivot ? (
      <g
        key={p.node.id}
        role="button"
        tabIndex={0}
        aria-label={`Investigate ${p.node.pivot}`}
        className="group cursor-pointer focus:outline-none"
        onClick={() => onPivot(p.node.pivot!)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPivot(p.node.pivot!); } }}
      >
        {body}
      </g>
    ) : <g key={p.node.id}>{body}</g>;
  };

  return (
    <section className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <h2 className="wb-label">Relationships</h2>
        <ul className="flex flex-wrap gap-x-3 gap-y-1">
          {kindsPresent.map(k => (
            <li key={k} className="flex items-center gap-1.5 text-[11px] text-fg-3">
              <span className={`w-2 h-2 rounded-full ${KIND_STYLE[k].dot}`} aria-hidden />{RELATION_LABEL[k]}
            </li>
          ))}
          <li className="text-[11px] text-fg-4">Badge = sources in agreement{onPivot ? ' · click a host or ASN to pivot' : ''}</li>
        </ul>
      </div>

      {/* Graph on wider screens */}
      <div className="hidden sm:block rounded-lg border border-line-soft bg-inset px-2 py-3 overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, minWidth: 640 }} className="block mx-auto" role="group" aria-label={`Relationships for ${indicator}`}>
          {left.placed.map(p => (
            <path key={`e-${p.node.id}`} d={edge(p, 'l')} fill="none" className={KIND_STYLE[p.node.kind].edge} strokeOpacity={0.55} strokeWidth={Math.min(1 + p.node.sources.length, 5)} />
          ))}
          {right.placed.map(p => (
            <path key={`e-${p.node.id}`} d={edge(p, 'r')} fill="none" className={KIND_STYLE[p.node.kind].edge} strokeOpacity={0.55} strokeWidth={Math.min(1 + p.node.sources.length, 5)} />
          ))}
          {[...left.headers, ...right.headers].map(h => (
            <text key={h.kind} x={h.x + 2} y={h.y} fontSize={10} fontWeight={600} letterSpacing=".06em" className="fill-fg-4">
              {RELATION_LABEL[h.kind].toUpperCase()} · {h.count}
            </text>
          ))}
          {left.placed.map(p => renderNode(p, 'l'))}
          {right.placed.map(p => renderNode(p, 'r'))}
          <rect x={CENTRE_X} y={cy - 17} width={CENTRE_W} height={34} rx={8} className="fill-rail stroke-c1" strokeWidth={1.5} />
          <text x={W / 2} y={cy + 4} textAnchor="middle" fontSize={12} fontWeight={600} className="fill-rail-fg-1 font-mono">{clip(indicator, 28)}</text>
        </svg>
      </div>

      {/* List on narrow screens */}
      <ul className="sm:hidden space-y-1">
        {nodes.map(n => (
          <li key={n.id} className="flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full shrink-0 ${KIND_STYLE[n.kind].dot}`} aria-hidden />
            <span className="text-fg-4 w-24 shrink-0">{n.role}</span>
            {onPivot && n.pivot ? (
              <button onClick={() => onPivot(n.pivot!)} className="font-mono text-accent-fg truncate hover:underline">{n.value}</button>
            ) : (
              <span className="font-mono text-fg-1 truncate">{n.value}</span>
            )}
            <span className="ml-auto text-[11px] text-fg-4 shrink-0">{n.sources.length}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
