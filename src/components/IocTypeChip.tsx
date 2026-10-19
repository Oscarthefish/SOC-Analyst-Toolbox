/**
 * Indicator types share one colour per family everywhere they appear:
 * network (IP, CIDR, ASN) blue, web (domain, URL) indigo, file hashes plum,
 * email raspberry, vulnerabilities teal. Leaked secrets use the danger colour.
 */

export const IOC_TYPE_LABEL: Record<string, string> = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email',
  asn: 'ASN', cidr: 'CIDR', cve: 'CVE', unknown: 'Unknown', headers: 'Headers', secret: 'Secret',
};

type Family = 'network' | 'web' | 'file' | 'email' | 'vuln' | 'secret' | 'none';

const FAMILY: Record<string, Family> = {
  ipv4: 'network', ipv6: 'network', cidr: 'network', asn: 'network',
  domain: 'web', url: 'web',
  md5: 'file', sha1: 'file', sha256: 'file',
  email: 'email', headers: 'email',
  cve: 'vuln',
  secret: 'secret',
};

const CHIP: Record<Family, string> = {
  network: 'bg-c1-bg text-c1-fg border-c1/30',
  web:     'bg-c2-bg text-c2-fg border-c2/30',
  file:    'bg-c3-bg text-c3-fg border-c3/30',
  email:   'bg-c4-bg text-c4-fg border-c4/30',
  vuln:    'bg-c5-bg text-c5-fg border-c5/30',
  secret:  'bg-danger-bg text-danger-fg border-danger-line',
  none:    'bg-raised text-fg-3 border-line',
};

const DOT: Record<Family, string> = {
  network: 'bg-c1', web: 'bg-c2', file: 'bg-c3', email: 'bg-c4', vuln: 'bg-c5', secret: 'bg-danger', none: 'bg-fg-4',
};

export const iocTypeDot = (type: string) => DOT[FAMILY[type] ?? 'none'];

export function IocTypeChip({ type, size = 'md' }: { type: string; size?: 'sm' | 'md' }) {
  return (
    <span className={`inline-flex items-center shrink-0 rounded border font-mono font-semibold ${CHIP[FAMILY[type] ?? 'none']} ${
      size === 'sm' ? 'h-[18px] px-1.5 text-[10px]' : 'h-[22px] px-2 text-[11px]'
    }`}>
      {IOC_TYPE_LABEL[type] ?? type}
    </span>
  );
}
