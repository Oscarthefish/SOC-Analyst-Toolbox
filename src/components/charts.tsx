import type { ReactNode } from 'react';
import { BUCKET_ORDER, BUCKET_LABEL } from '../lib/severityMix';
import type { Bucket } from '../lib/severityMix';

/**
 * Small SVG charts drawn with the theme tokens, so they follow light/dark mode
 * without a charting library. Every chart has a text equivalent for screen readers.
 */

export const BUCKET_FILL: Record<Bucket, string> = {
  critical: 'fill-danger', high: 'fill-high', medium: 'fill-warn', low: 'fill-c1',
  benign: 'fill-ok', info: 'fill-line-strong', none: 'fill-line',
};
export const BUCKET_STROKE: Record<Bucket, string> = {
  critical: 'stroke-danger', high: 'stroke-high', medium: 'stroke-warn', low: 'stroke-c1',
  benign: 'stroke-ok', info: 'stroke-line-strong', none: 'stroke-line',
};
export const BUCKET_BG: Record<Bucket, string> = {
  critical: 'bg-danger', high: 'bg-high', medium: 'bg-warn', low: 'bg-c1',
  benign: 'bg-ok', info: 'bg-line-strong', none: 'bg-line',
};

const describeMix = (mix: Record<Bucket, number>) =>
  BUCKET_ORDER.filter(b => mix[b] > 0).map(b => `${mix[b]} ${BUCKET_LABEL[b].toLowerCase()}`).join(', ');

// ── Ring gauge ───────────────────────────────────────────────────────────

interface RingProps {
  /** 0–1 */
  fraction: number;
  /** stroke-* class for the filled arc */
  tone: string;
  size?: number;
  thickness?: number;
  label: string;
  children?: ReactNode;
}

export function RingGauge({ fraction, tone, size = 88, thickness = 8, label, children }: RingProps) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const f = Math.max(0, Math.min(1, fraction));
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={label}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness} className="stroke-raised" />
        {f > 0 && (
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness} strokeLinecap="round"
            strokeDasharray={`${c * f} ${c}`} className={`${tone} transition-[stroke-dasharray] duration-500`}
          />
        )}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">{children}</div>
    </div>
  );
}

// ── Donut (severity mix) ─────────────────────────────────────────────────

export function SeverityDonut({ mix, size = 112, thickness = 14, children, label }: {
  mix: Record<Bucket, number>; size?: number; thickness?: number; children?: ReactNode; label: string;
}) {
  const total = BUCKET_ORDER.reduce((n, b) => n + mix[b], 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const gap = total > 1 ? 2 : 0;
  let offset = 0;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`${label}: ${describeMix(mix) || 'none'}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness} className="stroke-raised" />
        {total > 0 && BUCKET_ORDER.filter(b => mix[b] > 0).map(b => {
          const len = (mix[b] / total) * c;
          const el = (
            <circle
              key={b} cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness}
              strokeDasharray={`${Math.max(0, len - gap)} ${c}`} strokeDashoffset={-offset} className={BUCKET_STROKE[b]}
            />
          );
          offset += len;
          return el;
        })}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">{children}</div>
    </div>
  );
}

// ── Stacked bar (severity mix in one row) ────────────────────────────────

export function SeverityBar({ mix, label, height = 10 }: { mix: Record<Bucket, number>; label: string; height?: number }) {
  const total = BUCKET_ORDER.reduce((n, b) => n + mix[b], 0);
  return (
    <div className="flex w-full gap-[2px] rounded-full overflow-hidden bg-raised" style={{ height }} role="img" aria-label={`${label}: ${describeMix(mix) || 'none'}`}>
      {total > 0 && BUCKET_ORDER.filter(b => mix[b] > 0).map(b => (
        <span key={b} className={BUCKET_BG[b]} style={{ flexGrow: mix[b], flexBasis: 0 }} title={`${BUCKET_LABEL[b]}: ${mix[b]}`} />
      ))}
    </div>
  );
}

export function SeverityLegend({ mix, hideEmpty = true }: { mix: Record<Bucket, number>; hideEmpty?: boolean }) {
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1">
      {BUCKET_ORDER.filter(b => !hideEmpty || mix[b] > 0).map(b => (
        <li key={b} className="flex items-center gap-1.5 text-[11px] text-fg-3">
          <span className={`w-2 h-2 rounded-sm ${BUCKET_BG[b]}`} aria-hidden />
          {BUCKET_LABEL[b]}
          <span className="tabular-nums text-fg-1 font-medium">{mix[b]}</span>
        </li>
      ))}
    </ul>
  );
}

// ── Stacked columns (activity over time) ─────────────────────────────────

export interface Column {
  key: string;
  label: string;
  mix: Record<Bucket, number>;
}

export function SeverityColumns({ columns, height = 96, label }: { columns: Column[]; height?: number; label: string }) {
  const max = Math.max(1, ...columns.map(c => BUCKET_ORDER.reduce((n, b) => n + c.mix[b], 0)));
  return (
    <div role="img" aria-label={`${label}: ${columns.map(c => `${c.label} ${describeMix(c.mix) || 'none'}`).join('; ')}`}>
      <div className="flex items-end gap-1.5" style={{ height }}>
        {columns.map(c => {
          const total = BUCKET_ORDER.reduce((n, b) => n + c.mix[b], 0);
          return (
            <div key={c.key} className="flex-1 min-w-0 h-full flex flex-col justify-end" title={`${c.label}: ${total}`}>
              {total === 0 ? (
                <span className="block mx-auto w-full max-w-7 h-[2px] rounded-full bg-line" />
              ) : (
                <div className="mx-auto w-full max-w-7 flex flex-col-reverse gap-[2px] rounded-[3px] overflow-hidden" style={{ height: `${(total / max) * 100}%` }}>
                  {BUCKET_ORDER.filter(b => c.mix[b] > 0).reverse().map(b => (
                    <span key={b} className={BUCKET_BG[b]} style={{ flexGrow: c.mix[b], flexBasis: 0 }} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="flex gap-1.5 mt-1.5">
        {columns.map(c => (
          <span key={c.key} className="flex-1 min-w-0 text-center text-[10px] text-fg-4 truncate">{c.label}</span>
        ))}
      </div>
    </div>
  );
}
