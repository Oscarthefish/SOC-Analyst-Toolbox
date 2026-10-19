/**
 * Verdict scoring for /api/analyse: severity aggregation, provider contradictions
 * and VPN/Tor detection. Pure functions over adapter results.
 */
import type {
  EnrichmentResult,
  OverallAssessment,
  Severity,
  Confidence,
  ContradictionFlag,
} from '../types.js';

// Passive/contextual sources that should not contribute to severity scoring
export const PASSIVE_PROVIDERS = new Set(['bgpview', 'ipapi', 'ipinfo', 'torproject', 'whois', 'dns', 'dnsdumpster', 'crtsh', 'wayback', 'hunter']);

export function detectContradictions(results: EnrichmentResult[]): ContradictionFlag[] {
  const flags: ContradictionFlag[] = [];
  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');

  const activeSources = successful.filter(r => !PASSIVE_PROVIDERS.has(r.providerId));
  const highSeverity = activeSources.filter(r => r.severity === 'high' || r.severity === 'critical');
  const benignResults = activeSources.filter(r => r.severity === 'benign');

  // Contradiction: some sources say benign, others say malicious/high
  if (highSeverity.length > 0 && benignResults.length > 0) {
    flags.push({
      type: 'CONFLICT_BENIGN_VS_MALICIOUS',
      message: `${benignResults.map(r => r.providerName).join(', ')} classify as benign/clean, but ${highSeverity.map(r => r.providerName).join(', ')} flag as high severity or malicious.`,
      sources: [...highSeverity, ...benignResults].map(r => r.providerId),
      recommendation: 'Investigate whether this is shared infrastructure (CDN, hosting provider, VPN exit) where platform reputation does not reflect specific hosted content.',
    });
  }

  // Low-count VT detection with no corroboration
  const vtResult = successful.find(r => r.providerId === 'virustotal');
  if (vtResult && (vtResult.status === 'ok' || vtResult.status === 'cached')) {
    const malicious = vtResult.data.malicious as number | undefined;
    const harmless = vtResult.data.harmless as number | undefined;
    const undetected = vtResult.data.undetected as number | undefined;
    const suspicious = vtResult.data.suspicious as number | undefined;
    const total = (malicious ?? 0) + (harmless ?? 0) + (undetected ?? 0) + (suspicious ?? 0);
    if (malicious && malicious <= 2 && total > 10) {
      const otherHighResults = highSeverity.filter(r => r.providerId !== 'virustotal');
      if (otherHighResults.length === 0) {
        flags.push({
          type: 'LOW_DETECTION_NO_CORROBORATION',
          message: `VirusTotal shows only ${malicious}/${total} engine detections with no corroboration from other sources.`,
          sources: ['virustotal'],
          recommendation: 'Low-count VT detections without corroboration are often false positives. Consider sandbox analysis or additional context before acting.',
        });
      }
    }
  }

  // Newly registered domain with no detections
  const whoisResult = successful.find(r => r.providerId === 'whois');
  if (whoisResult && (whoisResult.status === 'ok' || whoisResult.status === 'cached')) {
    const age = whoisResult.data.domainAge;
    if (typeof age === 'number' && age >= 0 && age <= 14) {
      const anyThreat = activeSources.some(r =>
        r.severity === 'high' || r.severity === 'critical' || r.severity === 'medium');
      if (!anyThreat) {
        flags.push({
          type: 'NEWLY_REGISTERED_UNDETECTED',
          message: `Domain is only ${age} day(s) old but has no detections from checked sources.`,
          sources: ['whois'],
          recommendation: 'Newly registered domains with no detections are not confirmed benign. Absence of detection is not proof of safety for new domains — monitor closely.',
        });
      }
    }

    // DOMAIN_AGE_ARCHIVE_MISMATCH: WHOIS says old domain but Wayback has no or very recent archive
    const waybackResult = successful.find(r => r.providerId === 'wayback');
    if (
      waybackResult && (waybackResult.status === 'ok' || waybackResult.status === 'cached') &&
      typeof age === 'number' && age > 365
    ) {
      const firstArchivedFact = waybackResult.keyFacts?.find(f => f.label === 'First archived');
      if (!firstArchivedFact) {
        flags.push({
          type: 'DOMAIN_AGE_ARCHIVE_MISMATCH',
          message: `WHOIS shows domain age of ${age} days, but Wayback Machine has no archived snapshots for this domain.`,
          sources: ['whois', 'wayback'],
          recommendation: 'This may indicate a recently re-registered or re-purposed domain. The domain may have dropped and been re-registered, or never had a web presence. Treat as higher risk.',
        });
      } else {
        // Check if first archive is much more recent than WHOIS registration
        const firstDate = new Date(firstArchivedFact.value.split(' ')[0] ?? firstArchivedFact.value);
        const archiveDaysAgo = Math.floor((Date.now() - firstDate.getTime()) / 86_400_000);
        if (!isNaN(archiveDaysAgo) && age > 365 && archiveDaysAgo < 90) {
          flags.push({
            type: 'DOMAIN_AGE_ARCHIVE_MISMATCH',
            message: `WHOIS shows domain age of ${age} days, but Wayback Machine first snapshot is only ${archiveDaysAgo} day(s) ago. The domain may have been re-registered or repurposed.`,
            sources: ['whois', 'wayback'],
            recommendation: 'Domain re-registration is a common technique to abuse the reputation of expired domains. Check historical WHOIS records and compare with current content.',
          });
        }
      }
    }
  }

  return flags;
}

const VPN_ORG_KEYWORDS = [
  'mullvad', 'nordvpn', 'expressvpn', 'protonvpn', 'cyberghost', 'hidemyass',
  'ipvanish', 'surfshark', 'windscribe', 'privateinternetaccess', 'purevpn',
  'tunnelbear', 'astrill', 'ivpn', 'azirevpn', 'ovpn.com', 'airvpn',
  'anonymizer', 'anonymous proxy',
];

export interface VpnTorFlags {
  isTor: boolean;
  isVpn: boolean;
  signals: string[];
}

export function detectVpnOrTor(results: EnrichmentResult[]): VpnTorFlags {
  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');
  const signals: string[] = [];
  let isTor = false;
  let isVpn = false;

  for (const r of successful) {
    // TOR: authoritative signal from the torproject adapter
    if (r.providerId === 'torproject' && r.data.isTorNode === true) {
      isTor = true;
      const role = r.data.isExitNode ? 'exit node' : 'relay';
      signals.push(`Tor Project: confirmed TOR ${role}`);
    }

    // VPN: check org/ISP/name fields and usage type across all providers
    const fields = [
      typeof r.data.isp === 'string' ? r.data.isp : '',
      typeof r.data.name === 'string' ? r.data.name : '',
      typeof r.data.asName === 'string' ? r.data.asName : '',
      typeof r.data.org === 'string' ? r.data.org : '',
      typeof r.data.usageType === 'string' ? r.data.usageType : '',
    ].join(' ').toLowerCase();

    // "vpn" in org/ISP name is nearly always a commercial VPN provider
    if (fields.includes('vpn')) {
      isVpn = true;
      signals.push(`${r.providerName}: org/ISP name contains "vpn"`);
    }
    // Check well-known VPN provider names
    for (const kw of VPN_ORG_KEYWORDS) {
      if (fields.includes(kw)) {
        isVpn = true;
        if (!signals.some(s => s.startsWith(r.providerName))) {
          signals.push(`${r.providerName}: identified as ${kw}`);
        }
        break;
      }
    }
    // AbuseIPDB usageType explicitly set to VPN or anonymizer
    if (typeof r.data.usageType === 'string') {
      const ut = r.data.usageType.toLowerCase();
      if (ut.includes('vpn') || ut.includes('anonymiz') || ut.includes('proxy')) {
        isVpn = true;
        signals.push(`${r.providerName}: usage type "${r.data.usageType}"`);
      }
    }
  }

  return { isTor, isVpn, signals };
}

/**
 * Recommended actions per verdict. `highCorroborated` applies when two or more
 * sources agree on high (or high + medium); `high` when a single source says high.
 */
export interface ActionSet {
  critical: string[];
  highCorroborated: string[];
  high: string[];
  medium: string[];
  low: string[];
  benign: string[];
  unknown: string[];
  tor: string;
  vpn: string;
}

export const IOC_ACTIONS: ActionSet = {
  critical: [
    'Immediately isolate affected systems.',
    'Escalate to Tier 2/3 or incident response.',
    'Block IOC across all controls (firewall, proxy, EDR).',
    'Initiate incident response procedure.',
  ],
  highCorroborated: [
    'Block IOC at firewall and proxy.',
    'Search for related IOCs across environment.',
    'Escalate to senior analyst for review.',
  ],
  high: [
    'Block IOC at perimeter controls.',
    'Investigate correlated events in SIEM.',
  ],
  medium: [
    'Monitor for additional activity from this IOC.',
    'Consider adding to watchlist.',
  ],
  low: ['Log and monitor. No immediate action required.'],
  benign: ['No action required. Document findings.'],
  unknown: [
    'Insufficient data. Consider manual investigation.',
    'Check if additional API keys can be configured.',
  ],
  tor: 'Investigate all activity originating from this TOR node — high anonymity risk.',
  vpn: 'Note: IP belongs to a commercial VPN provider — identity obfuscation should be considered in context.',
};

export const EMAIL_ACTIONS: ActionSet = {
  critical: ['Block sender IP and domain immediately.', 'Escalate to incident response.'],
  highCorroborated: ['Block sending IP at perimeter.', 'Quarantine the email and notify the recipient.', 'Search mail logs for other messages from this sender.'],
  high: ['Block sending IP at perimeter.', 'Quarantine the email and notify the recipient.'],
  medium: ['Quarantine the email pending further review.', 'Monitor for similar messages from this sender/IP.'],
  low: ['Log and monitor. No immediate action required.'],
  benign: ['No action required. Document findings.'],
  unknown: ['Insufficient data. Consider manual investigation.'],
  tor: 'Sending IP is a Tor node — treat the message as anonymised and suspicious.',
  vpn: 'Sending IP belongs to a commercial VPN provider — sender identity is obscured.',
};

/**
 * The single verdict scorer used by every route. Passive context sources (WHOIS,
 * geolocation, DNS…) never drive severity; confidence reflects how many active
 * sources returned data and whether any of it is recent.
 */
export function computeOverallAssessment(
  results: EnrichmentResult[],
  vpnTor?: VpnTorFlags,
  actions: ActionSet = IOC_ACTIONS,
): OverallAssessment {
  const successful = results.filter(r => r.status === 'ok' || r.status === 'cached');
  // Only active (non-passive) sources contribute to severity
  const activeSources = successful.filter(r => !PASSIVE_PROVIDERS.has(r.providerId));

  const severityCounts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, benign: 0, unknown: 0,
  };
  for (const r of activeSources) {
    severityCounts[r.severity] = (severityCounts[r.severity] ?? 0) + 1;
  }

  let severity: Severity;
  let recommendedActions: string[];

  if (severityCounts.critical > 0) {
    severity = 'critical';
    recommendedActions = [...actions.critical];
  } else if (severityCounts.high >= 2 || (severityCounts.high >= 1 && severityCounts.medium >= 1)) {
    severity = 'high';
    recommendedActions = [...actions.highCorroborated];
  } else if (severityCounts.high >= 1) {
    severity = 'high';
    recommendedActions = [...actions.high];
  } else if (severityCounts.medium >= 1) {
    severity = 'medium';
    recommendedActions = [...actions.medium];
  } else if (severityCounts.low > 0) {
    severity = 'low';
    recommendedActions = [...actions.low];
  } else if (severityCounts.benign > 0 && severityCounts.unknown === 0) {
    severity = 'benign';
    recommendedActions = [...actions.benign];
  } else {
    severity = 'unknown';
    recommendedActions = [...actions.unknown];
  }

  // Confidence based on data quality: how many active sources returned data
  const activeDataCount = activeSources.length;
  const allHistorical = activeSources.every(r =>
    r.freshnessLabel === 'historical' || r.freshnessLabel === 'unknown');

  let confidence: Confidence;
  if (activeDataCount >= 3 && !allHistorical) {
    confidence = 'high';
  } else if (activeDataCount >= 1) {
    confidence = allHistorical ? 'low' : 'medium';
  } else {
    confidence = 'low';
  }

  // Elevate severity for VPN/TOR: these are active obfuscation tools — never leave as benign/unknown.
  if (vpnTor?.isTor && (severity === 'benign' || severity === 'unknown' || severity === 'low')) {
    severity = 'medium';
    recommendedActions.unshift(actions.tor);
  } else if (vpnTor?.isVpn && (severity === 'benign' || severity === 'unknown')) {
    severity = 'low';
    recommendedActions.unshift(actions.vpn);
  }

  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);
  const summary = successful.length === 0
    ? 'No enrichment providers returned data. Check API key configuration.'
    : `Aggregated assessment from ${successful.length} provider(s): ${severityLabel} severity, ${confidence} confidence.`;

  return { severity, confidence, summary, recommendedActions };
}
