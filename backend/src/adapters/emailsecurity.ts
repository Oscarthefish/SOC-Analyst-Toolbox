import dns from 'node:dns/promises';
import type { IocInput, EnrichmentResult, EnrichOptions, Severity } from '../types.js';
import { resultFactory } from '../lib/result.js';

const PROVIDER_ID = 'emailsecurity';
const PROVIDER_NAME = 'Email Security (DNS)';
const makeResult = resultFactory(PROVIDER_ID, PROVIDER_NAME);

// Common DKIM selectors to probe
const DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'amazonses',
  'mandrill', 'sendgrid', 's1', 's2', 'k1', 'k2',
  'mail', 'email', 'dkim', 'proofpoint', 'mimecast',
];

async function queryTxt(hostname: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(hostname);
    return records.map(parts => parts.join(''));
  } catch {
    return [];
  }
}

export async function emailsecurity(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'domain') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Email Security does not support IOC type: ${ioc.type} (supports: domain).`,
    });
  }

  const domain = ioc.normalised;
  const issues: string[] = [];
  const positives: string[] = [];

  // --- SPF ---
  const spfRecords = (await queryTxt(domain)).filter(r => r.toLowerCase().startsWith('v=spf1'));
  let spfPolicy = 'missing';
  if (spfRecords.length === 0) {
    issues.push('SPF record absent');
  } else {
    const spf = spfRecords[0];
    if (spf.includes('+all')) {
      spfPolicy = '+all (permissive — HIGH)';
      issues.push('SPF +all allows any sender to pass');
    } else if (spf.includes('~all')) {
      spfPolicy = '~all (soft-fail — MEDIUM)';
      issues.push('SPF ~all soft-fail still permits spoofed delivery');
    } else if (spf.includes('-all')) {
      spfPolicy = '-all (strict)';
      positives.push('SPF hard-fail (-all) enforced');
    } else {
      spfPolicy = 'no all mechanism';
      issues.push('SPF has no explicit all mechanism');
    }
  }

  // --- DMARC ---
  const dmarcRecords = (await queryTxt(`_dmarc.${domain}`)).filter(r =>
    r.toLowerCase().includes('v=dmarc1'),
  );
  let dmarcPolicy = 'missing';
  let dmarcRua = '';
  if (dmarcRecords.length === 0) {
    issues.push('DMARC record absent');
  } else {
    const dmarc = dmarcRecords[0];
    const pMatch = dmarc.match(/p=(\w+)/i);
    dmarcPolicy = pMatch?.[1]?.toLowerCase() ?? 'unknown';
    const ruaMatch = dmarc.match(/rua=([^;]+)/i);
    dmarcRua = ruaMatch?.[1] ?? '';
    if (dmarcPolicy === 'none') {
      issues.push('DMARC p=none (monitoring only — no enforcement)');
    } else if (dmarcPolicy === 'quarantine') {
      issues.push('DMARC p=quarantine (partial enforcement)');
    } else if (dmarcPolicy === 'reject') {
      positives.push('DMARC p=reject (strict enforcement)');
    }
  }

  // --- DKIM selectors ---
  const foundSelectors: string[] = [];
  await Promise.all(
    DKIM_SELECTORS.map(async sel => {
      const records = await queryTxt(`${sel}._domainkey.${domain}`);
      if (records.some(r => r.toLowerCase().includes('v=dkim1') || r.includes('p='))) {
        foundSelectors.push(sel);
      }
    }),
  );

  if (foundSelectors.length === 0) {
    issues.push('No DKIM selectors found (probed 16 common selectors)');
  } else {
    positives.push(`DKIM active (selectors: ${foundSelectors.join(', ')})`);
  }

  // --- Severity ---
  let severity: Severity;
  const criticalIssues = issues.filter(
    i => i.includes('absent') || i.includes('+all') || i.includes('p=none'),
  );
  if (criticalIssues.length >= 2) {
    severity = 'high';
  } else if (criticalIssues.length === 1 || issues.some(i => i.includes('~all') || i.includes('quarantine'))) {
    severity = 'medium';
  } else if (issues.length > 0) {
    severity = 'low';
  } else {
    severity = 'benign';
  }

  const summaryParts: string[] = [];
  if (issues.length > 0) summaryParts.push(`Issues: ${issues.join('; ')}`);
  if (positives.length > 0) summaryParts.push(`OK: ${positives.join('; ')}`);

  return makeResult({
    status: 'ok',
    summary: `Email Security (${domain}): ${summaryParts.join(' | ') || 'No data returned'}`,
    severity,
    confidence: 'high',
    data: {
      spfPolicy,
      dmarcPolicy,
      dmarcRua: dmarcRua || undefined,
      dkimSelectors: foundSelectors,
      issues,
      positives,
    },
    sourceReliability: 'authoritative',
    keyFacts: [
      { label: 'SPF policy', value: spfPolicy },
      { label: 'DMARC policy', value: dmarcPolicy },
      { label: 'DKIM selectors', value: foundSelectors.length > 0 ? foundSelectors.join(', ') : 'none found' },
      ...(dmarcRua ? [{ label: 'DMARC reports → ', value: dmarcRua }] : []),
    ],
  });
}
