/**
 * A curated subset of MITRE ATT&CK (Enterprise) covering techniques that
 * indicator-led investigations commonly touch. Names and tactic assignments
 * follow attack.mitre.org; techniques reported by providers that are not listed
 * here are still shown, with the provider's name for them.
 */

export interface Tactic {
  id: string;
  name: string;
  /** Ramp colour group for the kill-chain phase (see --color-c* tokens) */
  phase: 'c5' | 'c1' | 'c2' | 'c3' | 'c4';
}

// Kill-chain order; phases group neighbouring tactics under one colour
export const TACTICS: Tactic[] = [
  { id: 'TA0043', name: 'Reconnaissance', phase: 'c5' },
  { id: 'TA0042', name: 'Resource Development', phase: 'c5' },
  { id: 'TA0001', name: 'Initial Access', phase: 'c1' },
  { id: 'TA0002', name: 'Execution', phase: 'c1' },
  { id: 'TA0003', name: 'Persistence', phase: 'c2' },
  { id: 'TA0004', name: 'Privilege Escalation', phase: 'c2' },
  { id: 'TA0005', name: 'Defense Evasion', phase: 'c2' },
  { id: 'TA0006', name: 'Credential Access', phase: 'c3' },
  { id: 'TA0007', name: 'Discovery', phase: 'c3' },
  { id: 'TA0008', name: 'Lateral Movement', phase: 'c3' },
  { id: 'TA0009', name: 'Collection', phase: 'c4' },
  { id: 'TA0011', name: 'Command and Control', phase: 'c4' },
  { id: 'TA0010', name: 'Exfiltration', phase: 'c4' },
  { id: 'TA0040', name: 'Impact', phase: 'c4' },
];

export interface Technique {
  id: string;
  name: string;
  /** Tactic ids, first is the primary one used for grouping */
  tactics: string[];
}

const t = (id: string, name: string, ...tactics: string[]): Technique => ({ id, name, tactics });

export const TECHNIQUES: Technique[] = [
  // Reconnaissance / Resource Development
  t('T1595', 'Active Scanning', 'TA0043'),
  t('T1595.001', 'Scanning IP Blocks', 'TA0043'),
  t('T1595.002', 'Vulnerability Scanning', 'TA0043'),
  t('T1598', 'Phishing for Information', 'TA0043'),
  t('T1583', 'Acquire Infrastructure', 'TA0042'),
  t('T1583.001', 'Domains', 'TA0042'),
  t('T1584', 'Compromise Infrastructure', 'TA0042'),

  // Initial Access / Execution
  t('T1566', 'Phishing', 'TA0001'),
  t('T1566.001', 'Spearphishing Attachment', 'TA0001'),
  t('T1566.002', 'Spearphishing Link', 'TA0001'),
  t('T1190', 'Exploit Public-Facing Application', 'TA0001'),
  t('T1133', 'External Remote Services', 'TA0001', 'TA0003'),
  t('T1189', 'Drive-by Compromise', 'TA0001'),
  t('T1078', 'Valid Accounts', 'TA0001', 'TA0003', 'TA0004', 'TA0005'),
  t('T1078.004', 'Cloud Accounts', 'TA0001', 'TA0003', 'TA0004', 'TA0005'),
  t('T1204', 'User Execution', 'TA0002'),
  t('T1204.001', 'Malicious Link', 'TA0002'),
  t('T1204.002', 'Malicious File', 'TA0002'),
  t('T1059', 'Command and Scripting Interpreter', 'TA0002'),
  t('T1059.001', 'PowerShell', 'TA0002'),

  // Persistence / Privilege Escalation / Defense Evasion
  t('T1505.003', 'Web Shell', 'TA0003'),
  t('T1098', 'Account Manipulation', 'TA0003', 'TA0004'),
  t('T1068', 'Exploitation for Privilege Escalation', 'TA0004'),
  t('T1027', 'Obfuscated Files or Information', 'TA0005'),
  t('T1218', 'System Binary Proxy Execution', 'TA0005'),

  // Credential Access / Discovery / Lateral Movement
  t('T1110', 'Brute Force', 'TA0006'),
  t('T1110.001', 'Password Guessing', 'TA0006'),
  t('T1110.003', 'Password Spraying', 'TA0006'),
  t('T1110.004', 'Credential Stuffing', 'TA0006'),
  t('T1555', 'Credentials from Password Stores', 'TA0006'),
  t('T1539', 'Steal Web Session Cookie', 'TA0006'),
  t('T1557', 'Adversary-in-the-Middle', 'TA0006', 'TA0009'),
  t('T1046', 'Network Service Discovery', 'TA0007'),
  t('T1021', 'Remote Services', 'TA0008'),
  t('T1021.001', 'Remote Desktop Protocol', 'TA0008'),
  t('T1021.004', 'SSH', 'TA0008'),

  // Collection / Command and Control / Exfiltration / Impact
  t('T1114', 'Email Collection', 'TA0009'),
  t('T1114.003', 'Email Forwarding Rule', 'TA0009'),
  t('T1071', 'Application Layer Protocol', 'TA0011'),
  t('T1071.001', 'Web Protocols', 'TA0011'),
  t('T1071.004', 'DNS', 'TA0011'),
  t('T1090', 'Proxy', 'TA0011'),
  t('T1090.003', 'Multi-hop Proxy', 'TA0011'),
  t('T1105', 'Ingress Tool Transfer', 'TA0011'),
  t('T1568', 'Dynamic Resolution', 'TA0011'),
  t('T1568.002', 'Domain Generation Algorithms', 'TA0011'),
  t('T1571', 'Non-Standard Port', 'TA0011'),
  t('T1572', 'Protocol Tunneling', 'TA0011'),
  t('T1573', 'Encrypted Channel', 'TA0011'),
  t('T1041', 'Exfiltration Over C2 Channel', 'TA0010'),
  t('T1048', 'Exfiltration Over Alternative Protocol', 'TA0010'),
  t('T1567', 'Exfiltration Over Web Service', 'TA0010'),
  t('T1567.002', 'Exfiltration to Cloud Storage', 'TA0010'),
  t('T1486', 'Data Encrypted for Impact', 'TA0040'),
  t('T1490', 'Inhibit System Recovery', 'TA0040'),
  t('T1496', 'Resource Hijacking', 'TA0040'),
  t('T1498', 'Network Denial of Service', 'TA0040'),
];

export const TECHNIQUE_BY_ID = new Map(TECHNIQUES.map(x => [x.id, x]));
export const TACTIC_BY_ID = new Map(TACTICS.map(x => [x.id, x]));

/** Link to the technique on attack.mitre.org (sub-techniques use a slash). */
export function attackUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}
