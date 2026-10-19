import type { IocType } from '../types/ioc';
import { isIpv4, isIpv4Cidr, isIpv6 } from './ipUtils';

// Common valid TLDs to reduce false positives (not exhaustive, but covers the vast majority)
const VALID_TLDS = new Set([
  'ac','ad','ae','af','ag','ai','al','am','ao','aq','ar','as','at','au','aw','ax','az',
  'ba','bb','bd','be','bf','bg','bh','bi','bj','bm','bn','bo','br','bs','bt','bv','bw','by','bz',
  'ca','cc','cd','cf','cg','ch','ci','ck','cl','cm','cn','co','cr','cu','cv','cw','cx','cy','cz',
  'de','dj','dk','dm','do','dz','ec','ee','eg','er','es','et','eu','fi','fj','fk','fm','fo','fr',
  'ga','gb','gd','ge','gf','gg','gh','gi','gl','gm','gn','gp','gq','gr','gs','gt','gu','gw','gy',
  'hk','hm','hn','hr','ht','hu','id','ie','il','im','in','io','iq','ir','is','it',
  'je','jm','jo','jp','ke','kg','kh','ki','km','kn','kp','kr','kw','ky','kz',
  'la','lb','lc','li','lk','lr','ls','lt','lu','lv','ly',
  'ma','mc','md','me','mg','mh','mk','ml','mm','mn','mo','mp','mq','mr','ms','mt','mu','mv','mw','mx','my','mz',
  'na','nc','ne','nf','ng','ni','nl','no','np','nr','nu','nz',
  'om','pa','pe','pf','pg','ph','pk','pl','pm','pn','pr','ps','pt','pw','py',
  'qa','re','ro','rs','ru','rw',
  'sa','sb','sc','sd','se','sg','sh','si','sj','sk','sl','sm','sn','so','sr','ss','st','sv','sx','sy','sz',
  'tc','td','tf','tg','th','tj','tk','tl','tm','tn','to','tr','tt','tv','tw','tz',
  'ua','ug','uk','us','uy','uz',
  'va','vc','ve','vg','vi','vn','vu','wf','ws',
  'ye','yt','za','zm','zw',
  // Generic TLDs
  'com','net','org','edu','gov','mil','int',
  'info','biz','name','pro','aero','coop','museum','mobi','travel','jobs','tel',
  'cat','post','xxx','local',
  // Common new gTLDs
  'io','ai','app','dev','tech','online','site','website','store','shop','blog','cloud',
  'digital','global','media','news','agency','consulting','services','solutions',
  'security','cyber','network','systems','software','finance','bank','health','care',
  'academy','college','university','school','foundation','institute',
]);

// Version strings pattern to exclude (e.g., 1.0.0, 2.3.1, 10.4.2)
const VERSION_RE = /^\d+\.\d+(\.\d+)*([a-zA-Z]\w*)?$/;

// File extensions to exclude as standalone strings
const FILE_EXTENSION_RE = /^\.\w{2,6}$/;

// Known file extension suffixes that indicate not-a-domain
const FILENAME_EXTENSIONS = new Set([
  'exe','dll','pdf','doc','docx','xls','xlsx','ppt','pptx','zip','rar','7z','tar','gz',
  'txt','csv','json','xml','html','htm','js','ts','jsx','tsx','py','rb','php','sh','bat',
  'ps1','vbs','hta','lnk','iso','img','bin','dat','log','tmp','bak','cfg','ini','conf',
  'jpg','jpeg','png','gif','bmp','svg','ico','webp','mp4','mp3','wav','avi','mkv',
  'pkg','dmg','deb','rpm','msi','cab',
]);

export interface ExtractedIoc {
  raw: string;
  type: IocType;
  normalised: string;
  suggestedWorkflowIds: string[];
}

// Map IOC types to likely workflow IDs
const TYPE_WORKFLOW_MAP: Record<string, string[]> = {
  ipv4: ['ip-triage', 'suspicious-connection'],
  ipv6: ['ip-triage', 'suspicious-connection'],
  domain: ['domain-triage', 'url-phishing'],
  url: ['url-phishing', 'domain-triage'],
  md5: ['malware-hash'],
  sha1: ['malware-hash'],
  sha256: ['malware-hash'],
  email: ['spam-source'],
  asn: ['ip-triage'],
  cidr: ['ip-triage'],
  cve: ['cve-context'],
};

function getSuggestedWorkflows(type: IocType): string[] {
  return TYPE_WORKFLOW_MAP[type] ?? [];
}

function isValidDomain(candidate: string): boolean {
  // Must have at least one dot
  if (!candidate.includes('.')) return false;

  // Exclude version strings
  if (VERSION_RE.test(candidate)) return false;

  // Exclude bare file extensions
  if (FILE_EXTENSION_RE.test(candidate)) return false;

  // Must match domain pattern
  if (!/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(candidate)) return false;

  // Extract TLD
  const parts = candidate.toLowerCase().split('.');
  const tld = parts[parts.length - 1];

  // Reject if TLD is a known file extension
  if (FILENAME_EXTENSIONS.has(tld)) return false;

  // TLD must be in the valid list
  if (!VALID_TLDS.has(tld)) return false;

  return true;
}

/** Refang common defanging so defanged indicators are extracted whole. */
function refangText(text: string): string {
  return text
    .replace(/\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}/gi, '.')
    .replace(/\[(?:@|at)\]|\((?:@|at)\)/gi, '@')
    .replace(/\[:\]/g, ':')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\bhxxp(s?)(?=:\/\/)/gi, 'http$1');
}

export function extractIocs(input: string): ExtractedIoc[] {
  const text = refangText(input);
  const results: ExtractedIoc[] = [];
  const seen = new Set<string>(); // deduplication key: type:normalised

  function add(raw: string, type: IocType, normalised: string) {
    const key = `${type}:${normalised}`;
    if (!seen.has(key)) {
      seen.add(key);
      results.push({ raw, type, normalised, suggestedWorkflowIds: getSuggestedWorkflows(type) });
    }
  }

  // --- CVE identifiers (must run before hash/domain to avoid false matches) ---
  const cveRe = /\b(CVE-\d{4}-\d{4,})\b/gi;
  for (const m of text.matchAll(cveRe)) {
    add(m[1], 'cve', m[1].toUpperCase());
  }

  // --- SHA256 (64 hex chars) ---
  const sha256Re = /\b([0-9a-fA-F]{64})\b/g;
  for (const m of text.matchAll(sha256Re)) {
    add(m[1], 'sha256', m[1].toLowerCase());
  }

  // --- SHA1 (40 hex chars) ---
  const sha1Re = /\b([0-9a-fA-F]{40})\b/g;
  for (const m of text.matchAll(sha1Re)) {
    add(m[1], 'sha1', m[1].toLowerCase());
  }

  // --- MD5 (32 hex chars) ---
  const md5Re = /\b([0-9a-fA-F]{32})\b/g;
  for (const m of text.matchAll(md5Re)) {
    add(m[1], 'md5', m[1].toLowerCase());
  }

  // --- ASN ---
  const asnRe = /\b(AS\d+)\b/gi;
  for (const m of text.matchAll(asnRe)) {
    add(m[1], 'asn', m[1].toUpperCase());
  }

  // --- IPv4 CIDR ---
  const cidrRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})\b/g;
  for (const m of text.matchAll(cidrRe)) {
    if (isIpv4Cidr(m[1])) {
      add(m[1], 'cidr', m[1]);
    }
  }

  // --- IPv4 (the lookahead skips a CIDR's network address) ---
  const ipv4Re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b(?!\/\d)/g;
  for (const m of text.matchAll(ipv4Re)) {
    if (isIpv4(m[1])) {
      add(m[1], 'ipv4', m[1]);
    }
  }

  // --- IPv6 (candidates validated strictly, so timestamps like 12:30:45 are ignored) ---
  const ipv6Re = /(?<![\w:])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![\w:])/g;
  for (const m of text.matchAll(ipv6Re)) {
    if (isIpv6(m[1])) {
      add(m[1], 'ipv6', m[1].toLowerCase());
    }
  }

  // Collect already-identified IP/CIDR values to exclude from domain matching
  const knownIpValues = new Set(
    results
      .filter(r => r.type === 'ipv4' || r.type === 'ipv6' || r.type === 'cidr')
      .map(r => r.normalised)
  );

  // --- Email addresses (before domain extraction to avoid partial matches) ---
  const emailRe = /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
  const emailHostnames = new Set<string>();
  for (const m of text.matchAll(emailRe)) {
    const emailLower = m[1].toLowerCase();
    add(m[1], 'email', emailLower);
    // Track domain part of email to avoid duplicating as domain
    const atIdx = emailLower.indexOf('@');
    if (atIdx !== -1) emailHostnames.add(emailLower.slice(atIdx + 1));
  }

  // --- URLs (http/https) ---
  // Brackets are escaped for readability in this negated URL character class.
  // eslint-disable-next-line no-useless-escape
  const urlRe = /\bhttps?:\/\/[^\s<>"'`\]\[{}|\\^]+/gi;
  const urlHostnames = new Set<string>();
  for (const m of text.matchAll(urlRe)) {
    const url = m[0].replace(/[.,;:!?)]+$/, ''); // strip trailing punctuation
    try {
      const parsed = new URL(url);
      urlHostnames.add(parsed.hostname.toLowerCase().replace(/^www\./, ''));
      add(url, 'url', url);
    } catch {
      // skip invalid
    }
  }

  // --- Domains ---
  // Match potential domain-like tokens (word chars + dots + word chars)
  const domainRe = /\b([a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+)\b/g;
  for (const m of text.matchAll(domainRe)) {
    const candidate = m[1].toLowerCase();

    // Skip if already captured as IP
    if (knownIpValues.has(candidate)) continue;

    // Skip if this is the hostname from a URL or email
    if (urlHostnames.has(candidate) || emailHostnames.has(candidate)) continue;

    // Apply domain validity checks
    if (!isValidDomain(candidate)) continue;

    // Skip if already matched as sha/md5/asn
    if (seen.has(`sha256:${candidate}`) || seen.has(`sha1:${candidate}`) || seen.has(`md5:${candidate}`)) continue;

    add(m[1], 'domain', candidate);
  }

  // Sort: CVEs and hashes first, then IPs, then domains/URLs, then email, then ASN/CIDR
  const ORDER: IocType[] = ['cve', 'sha256', 'sha1', 'md5', 'ipv4', 'ipv6', 'url', 'domain', 'email', 'asn', 'cidr'];
  results.sort((a, b) => {
    const ai = ORDER.indexOf(a.type);
    const bi = ORDER.indexOf(b.type);
    return ai - bi;
  });

  return results;
}
