import type { DetectedIoc } from '../types/ioc';
import { WarningBanner } from './WarningBanner';
import { CopyButton } from './CopyButton';

interface DetectionPanelProps {
  ioc: DetectedIoc | null;
}

const TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5 Hash',
  sha1: 'SHA1 Hash',
  sha256: 'SHA256 Hash',
  email: 'Email Address',
  asn: 'ASN',
  cidr: 'CIDR',
  unknown: 'Unknown',
};

const TYPE_COLORS: Record<string, string> = {
  ipv4: 'bg-blue-900/60 text-blue-300 border-blue-700',
  ipv6: 'bg-blue-900/60 text-blue-300 border-blue-700',
  domain: 'bg-purple-900/60 text-purple-300 border-purple-700',
  url: 'bg-indigo-900/60 text-indigo-300 border-indigo-700',
  md5: 'bg-orange-900/60 text-orange-300 border-orange-700',
  sha1: 'bg-orange-900/60 text-orange-300 border-orange-700',
  sha256: 'bg-orange-900/60 text-orange-300 border-orange-700',
  email: 'bg-teal-900/60 text-teal-300 border-teal-700',
  asn: 'bg-slate-700/60 text-slate-300 border-slate-600',
  cidr: 'bg-slate-700/60 text-slate-300 border-slate-600',
  unknown: 'bg-red-900/40 text-red-400 border-red-800',
};

export function DetectionPanel({ ioc }: DetectionPanelProps) {
  if (!ioc) {
    return (
      <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-3">Detection</h2>
        <p className="text-slate-500 text-sm">Enter an IP, domain, URL, hash, email, ASN or CIDR to begin.</p>
      </div>
    );
  }

  const typeLabel = TYPE_LABELS[ioc.type] ?? ioc.type;
  const typeColor = TYPE_COLORS[ioc.type] ?? TYPE_COLORS.unknown;

  return (
    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4 space-y-3">
      <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Detection</h2>

      <div className="flex flex-wrap gap-2 items-center">
        <span className={`inline-flex items-center px-2.5 py-1 rounded border text-xs font-semibold ${typeColor}`}>
          {typeLabel}
        </span>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs border ${
          ioc.confidence === 'high'
            ? 'bg-green-900/40 text-green-400 border-green-800'
            : ioc.confidence === 'medium'
            ? 'bg-amber-900/40 text-amber-400 border-amber-800'
            : 'bg-red-900/40 text-red-400 border-red-800'
        }`}>
          {ioc.confidence} confidence
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 text-sm">
        <div className="flex items-start gap-2">
          <span className="text-slate-500 w-20 shrink-0">Original:</span>
          <code className="text-slate-300 text-xs bg-slate-900/60 px-2 py-0.5 rounded break-all flex-1">{ioc.original}</code>
          <CopyButton text={ioc.original} label="original" />
        </div>
        {ioc.normalised !== ioc.original.trim() && (
          <div className="flex items-start gap-2">
            <span className="text-slate-500 w-20 shrink-0">Normalised:</span>
            <code className="text-slate-300 text-xs bg-slate-900/60 px-2 py-0.5 rounded break-all flex-1">{ioc.normalised}</code>
            <CopyButton text={ioc.normalised} label="normalised" />
          </div>
        )}
      </div>

      {ioc.type === 'url' && ioc.urlExtract && (
        <div className="border-t border-slate-700 pt-3">
          <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-semibold">URL Breakdown</p>
          <div className="grid grid-cols-1 gap-1 text-xs">
            {[
              { label: 'Scheme', value: ioc.urlExtract.scheme },
              { label: 'Hostname', value: ioc.urlExtract.hostname },
              { label: 'Domain', value: ioc.urlExtract.domain },
              { label: 'Path', value: ioc.urlExtract.path || '/' },
              ioc.urlExtract.query ? { label: 'Query', value: ioc.urlExtract.query } : null,
              ioc.urlExtract.queryParamNames.length ? { label: 'Params', value: ioc.urlExtract.queryParamNames.join(', ') } : null,
            ].filter(Boolean).map((row) => (
              <div key={row!.label} className="flex gap-2">
                <span className="text-slate-500 w-16 shrink-0">{row!.label}:</span>
                <code className="text-slate-300 bg-slate-900/60 px-1.5 rounded break-all">{row!.value}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {ioc.isSensitiveUrl && (
        <WarningBanner
          type="danger"
          message="Sensitive URL detected"
          details={ioc.sensitiveUrlWarning}
        />
      )}

      {ioc.type === 'unknown' && (
        <WarningBanner
          type="warning"
          message="IOC type not recognised"
          details="Check the input format. Supported: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, email, ASN (AS12345), CIDR (192.168.1.0/24)."
        />
      )}
    </div>
  );
}
