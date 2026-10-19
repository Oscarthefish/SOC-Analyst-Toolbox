/**
 * Pivot tools have ~25 free-text categories; colour them by five families instead
 * so the library stays readable. Custom categories fall back by keyword.
 */

export type ToolFamily = 'intel' | 'web' | 'malware' | 'infra' | 'business';

export const TOOL_FAMILY_LABEL: Record<ToolFamily, string> = {
  intel: 'Threat intel & reputation',
  web: 'Web, URL & phishing',
  malware: 'Malware & files',
  infra: 'Infrastructure & DNS',
  business: 'Business OSINT',
};

export const TOOL_FAMILY_ORDER: ToolFamily[] = ['intel', 'web', 'malware', 'infra', 'business'];

const RULES: [RegExp, ToolFamily][] = [
  [/business/i, 'business'],
  [/dark web|ransomware|fraud|proxy|vpn/i, 'intel'],
  [/malware|sandbox|decod|file/i, 'malware'],
  [/url|web|phish/i, 'web'],
  [/dns|whois|registr|certificate|exposure|email|osint/i, 'infra'],
];

export function toolFamily(category: string): ToolFamily {
  for (const [re, fam] of RULES) if (re.test(category)) return fam;
  return 'intel';
}
