import type { CaseVerdict, CaseConfidence } from '../types/case';
import type { IocType } from '../types/ioc';

export const VERDICT_OPTIONS: { value: CaseVerdict; label: string }[] = [
  { value: 'benign', label: 'Benign' },
  { value: 'known_scanner_noise', label: 'Known scanner / Internet noise' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'likely_malicious', label: 'Likely malicious' },
  { value: 'confirmed_malicious', label: 'Confirmed malicious' },
  { value: 'inconclusive', label: 'Inconclusive' },
];

export const CONFIDENCE_OPTIONS: { value: CaseConfidence; label: string }[] = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
];

export const ACTION_OPTIONS: string[] = [
  'Block IP/domain/URL',
  'Quarantine email',
  'Isolate endpoint',
  'Reset password',
  'Revoke sessions',
  'Report/takedown',
  'Tune detection',
  'Close as benign/noise',
  'Escalate to senior analyst',
  'Monitor only',
];

export function generateAssessmentSummary(
  verdict: CaseVerdict | '',
  confidence: CaseConfidence | '',
  iocType: IocType | '',
  actionsTaken: string[],
): string {
  if (!verdict) return '';

  const typeLabel = iocType
    ? {
        ipv4: 'IP address',
        ipv6: 'IPv6 address',
        domain: 'domain',
        url: 'URL',
        md5: 'file hash (MD5)',
        sha1: 'file hash (SHA1)',
        sha256: 'file hash (SHA256)',
        email: 'email address',
        asn: 'ASN',
        cidr: 'CIDR range',
        cve: 'CVE',
        secret: 'credential or secret',
        unknown: 'indicator',
      }[iocType] ?? 'indicator'
    : 'indicator';

  const confidenceStr = confidence ? ` with ${confidence} confidence` : '';

  let summary = '';

  switch (verdict) {
    case 'benign':
      summary = `The investigated ${typeLabel} has been assessed as benign${confidenceStr}. No malicious activity was identified. No action required beyond standard logging.`;
      break;
    case 'known_scanner_noise':
      summary = `The investigated ${typeLabel} appears to be known internet background noise or a mass scanner${confidenceStr}. This activity is not targeted. Consider tuning the detection to reduce false positives.`;
      break;
    case 'suspicious':
      summary = `The investigated ${typeLabel} is assessed as suspicious${confidenceStr}. Further investigation is recommended. Evidence is inconclusive but warrants continued monitoring or escalation.`;
      break;
    case 'likely_malicious':
      summary = `The investigated ${typeLabel} is assessed as likely malicious${confidenceStr}. Multiple indicators support a malicious classification. Immediate response actions are recommended.`;
      break;
    case 'confirmed_malicious':
      summary = `The investigated ${typeLabel} has been confirmed as malicious${confidenceStr}. This indicator is definitively associated with malicious activity. Containment and response actions should be executed immediately.`;
      break;
    case 'inconclusive':
      summary = `The investigation of this ${typeLabel} is inconclusive${confidenceStr}. Insufficient data is available to make a definitive determination. Continued monitoring or additional data sources are required.`;
      break;
  }

  if (actionsTaken.length > 0) {
    summary += `\n\nRecommended actions: ${actionsTaken.join(', ')}.`;
  }

  return summary;
}
