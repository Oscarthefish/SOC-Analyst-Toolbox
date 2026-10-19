import { useState, useEffect, useCallback } from 'react';
import { getKeyStatus, saveApiKey } from '../lib/apiClient';

interface SecondaryField {
  id: string;
  label: string;
}

interface Provider {
  id: string;
  name: string;
  description: string;
  signupUrl: string;
  tier: string;
  supports: string[];
  note?: string;
  secondaryField?: SecondaryField;
}

const PROVIDERS: Provider[] = [
  {
    id: 'GREYNOISE_API_KEY',
    name: 'GreyNoise',
    description: 'IP noise classification — identifies internet scanners, crawlers and known benign/malicious sources.',
    signupUrl: 'https://www.greynoise.io/signup',
    tier: 'Free community tier available',
    supports: ['IPv4', 'IPv6'],
    note: 'Community API is used by default with no key required. A paid key unlocks higher rate limits and additional data.',
  },
  {
    id: 'ABUSEIPDB_API_KEY',
    name: 'AbuseIPDB',
    description: 'Community IP abuse reporting — abuse confidence score, report count, ISP, usage type.',
    signupUrl: 'https://www.abuseipdb.com/register',
    tier: 'Free — 1,000 checks/day',
    supports: ['IPv4', 'IPv6'],
  },
  {
    id: 'IPINFO_TOKEN',
    name: 'IPinfo',
    description: 'IP geolocation and ASN data. Privacy plan also returns VPN/proxy/Tor flags.',
    signupUrl: 'https://ipinfo.io/signup',
    tier: 'Free — 50,000 requests/month',
    supports: ['IPv4', 'IPv6'],
  },
  {
    id: 'VIRUSTOTAL_API_KEY',
    name: 'VirusTotal',
    description: 'Multi-engine malware and reputation lookup for IPs, domains and file hashes.',
    signupUrl: 'https://www.virustotal.com/gui/join-us',
    tier: 'Free — 4 requests/min, 500/day',
    supports: ['IPv4', 'IPv6', 'Domain', 'MD5', 'SHA1', 'SHA256'],
    note: 'Lookup only. File upload and URL submission are intentionally disabled.',
  },
  {
    id: 'URLSCAN_API_KEY',
    name: 'urlscan.io',
    description: 'Search historical URL scans for domains and IPs. Search works without a key; key increases rate limits.',
    signupUrl: 'https://urlscan.io/user/register',
    tier: 'Free account — optional but recommended',
    supports: ['Domain', 'URL', 'IPv4'],
    note: 'Search only by default. URL submission is disabled unless explicitly enabled.',
  },
  {
    id: 'SHODAN_API_KEY',
    name: 'Shodan',
    description: 'Internet-wide scanner — shows open ports, services, banners and known vulnerabilities for a host.',
    signupUrl: 'https://account.shodan.io/register',
    tier: 'Paid API plan required for host lookups',
    supports: ['IPv4', 'IPv6'],
    note: 'Free Shodan accounts do not include API access. A paid membership or credits are required.',
  },
  {
    id: 'OTX_API_KEY',
    name: 'AlienVault OTX',
    description: 'Crowd-sourced threat intelligence — pulse feed covers IPs, domains, hashes, and URLs.',
    signupUrl: 'https://otx.alienvault.com/api',
    tier: 'Free',
    supports: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
  },
  {
    id: 'PULSEDIVE_API_KEY',
    name: 'Pulsedive',
    description: 'Threat intelligence with risk scoring and linked IOC relationships.',
    signupUrl: 'https://pulsedive.com/api',
    tier: 'Free tier available',
    supports: ['IPv4', 'IPv6', 'Domain', 'URL'],
  },
  {
    id: 'GOOGLE_SAFE_BROWSING_KEY',
    name: 'Google Safe Browsing',
    description: 'URL and domain reputation from Google\'s threat blocklists — malware, phishing, unwanted software.',
    signupUrl: 'https://developers.google.com/safe-browsing/v4/get-started',
    tier: 'Free — Google Cloud API key required',
    supports: ['URL', 'Domain'],
    note: 'Create a Google Cloud project, enable the Safe Browsing API, and generate an API key.',
  },
  {
    id: 'HIBP_API_KEY',
    name: 'HaveIBeenPwned',
    description: 'Email breach lookup — checks if an email address appears in known data breaches.',
    signupUrl: 'https://haveibeenpwned.com/API/Key',
    tier: 'Paid — $3.95/month',
    supports: ['Email'],
  },
  {
    id: 'HYBRID_ANALYSIS_KEY',
    name: 'Hybrid Analysis',
    description: 'Sandbox report lookup for file hashes — verdict, threat score, AV detections, malware family.',
    signupUrl: 'https://www.hybrid-analysis.com/apikeys/info',
    tier: 'Free account available',
    supports: ['MD5', 'SHA1', 'SHA256'],
    note: 'Use the API key from your Hybrid Analysis profile page.',
  },
  {
    id: 'THREATFOX_API_KEY',
    name: 'ThreatFox',
    description: 'abuse.ch IOC database — malware C2s, payloads, and threat actor infrastructure across all IOC types.',
    signupUrl: 'https://threatfox.abuse.ch/api/',
    tier: 'Free — register at threatfox.abuse.ch',
    supports: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    note: 'Free API key required. Use the same abuse.ch account for URLhaus and MalwareBazaar.',
  },
  {
    id: 'URLHAUS_API_KEY',
    name: 'URLhaus + MalwareBazaar',
    description: 'abuse.ch malicious URL database and malware hash lookup. One key covers both services.',
    signupUrl: 'https://urlhaus.abuse.ch/api/',
    tier: 'Free — register at abuse.ch',
    supports: ['IPv4', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    note: 'Same key authenticates both URLhaus (URLs/hosts) and MalwareBazaar (hashes). Auth-Key required as of 2025.',
  },
  {
    id: 'WHOISXMLAPI_KEY',
    name: 'WhoisXML API',
    description: 'Rich WHOIS data for domains and IPs — registrant, registrar, dates, nameservers. Falls back to free RDAP if no key.',
    signupUrl: 'https://main.whoisxmlapi.com/signup',
    tier: 'Free — 500 queries on signup',
    supports: ['Domain', 'IPv4', 'IPv6'],
    note: 'Without a key, free RDAP lookups are used automatically.',
  },
  {
    id: 'CENSYS_API_TOKEN',
    name: 'Censys',
    description: 'Internet exposure data — open ports, services, TLS certificates.',
    signupUrl: 'https://platform.censys.io',
    tier: 'Free — 100 credits/month',
    supports: ['IPv4', 'IPv6'],
    note: 'Generate a token at platform.censys.io → Settings → API Tokens. Token format: censys_xxxx…',
  },
  {
    id: 'DNSDUMPSTER_API_KEY',
    name: 'DNSDumpster',
    description: 'DNS recon API — enumerates A, MX, NS, TXT records, subdomains, and host infrastructure for a domain.',
    signupUrl: 'https://dnsdumpster.com/developer/',
    tier: 'Account required — free tier included',
    supports: ['Domain', 'URL'],
    note: 'API key is available from your DNSDumpster account dashboard at dnsdumpster.com/developer/',
  },
  {
    id: 'HUNTER_API_KEY',
    name: 'Hunter.io',
    description: 'Business domain intelligence — company profile, industry, employee count, email patterns, and indexed contact data.',
    signupUrl: 'https://hunter.io/users/sign_up',
    tier: 'Free — 25 requests/month',
    supports: ['Domain'],
    note: 'Free tier is limited to 25 domain searches per month. Results include company name, industry, and email pattern without returning individual email addresses.',
  },
];

interface CardState {
  inputValue: string;
  saving: boolean;
  saved: boolean;
  error: string | null;
}

function makeDefaultCardState(): CardState {
  return { inputValue: '', saving: false, saved: false, error: null };
}

interface ApiKeysPanelProps {
  backendOnline: boolean;
}

function StatusBadge({ configured }: { configured: boolean }) {
  if (configured) {
    return (
      <span className="inline-flex items-center gap-1.5 shrink-0 text-xs px-2 py-0.5 rounded bg-ok-bg border border-ok-line text-ok-fg font-medium">
        <span className="w-1.5 h-1.5 rounded-full bg-ok" />
        Configured
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 shrink-0 text-xs px-2 py-0.5 rounded bg-raised border border-line text-fg-2 font-medium">
      <span className="w-1.5 h-1.5 rounded-full bg-fg-4" />
      Not configured
    </span>
  );
}

export function ApiKeysPanel({ backendOnline }: ApiKeysPanelProps) {
  const [keyStatus, setKeyStatus] = useState<Record<string, boolean> | null>(null);
  const [loading, setLoading] = useState(false);
  const [cardState, setCardState] = useState<Record<string, CardState>>(() => {
    const entries = PROVIDERS.map(p => [p.id, makeDefaultCardState()]);
    PROVIDERS.forEach(p => {
      if (p.secondaryField) entries.push([p.secondaryField.id, makeDefaultCardState()]);
    });
    return Object.fromEntries(entries);
  });

  const fetchStatus = useCallback(async () => {
    if (!backendOnline) return;
    setLoading(true);
    const result = await getKeyStatus();
    setLoading(false);
    setKeyStatus(result);
  }, [backendOnline]);

  useEffect(() => {
    void fetchStatus();
  }, [fetchStatus]);

  function updateCard(id: string, patch: Partial<CardState>) {
    setCardState(prev => ({ ...prev, [id]: { ...prev[id], ...patch } }));
  }

  async function handleSave(provider: Provider) {
    const value = cardState[provider.id]?.inputValue ?? '';
    if (!value.trim()) return;

    updateCard(provider.id, { saving: true, error: null });

    const saves: Promise<{ ok: boolean; error?: string } | null>[] = [
      saveApiKey(provider.id, value.trim()),
    ];

    if (provider.secondaryField) {
      const secondaryValue = cardState[provider.secondaryField.id]?.inputValue ?? '';
      if (secondaryValue.trim()) {
        saves.push(saveApiKey(provider.secondaryField.id, secondaryValue.trim()));
      }
    }

    const results = await Promise.all(saves);
    updateCard(provider.id, { saving: false });

    const failed = results.find(r => !r || !r.ok);
    if (failed === null) {
      updateCard(provider.id, { error: 'Backend unreachable. Make sure the backend is running.' });
      return;
    }
    if (failed) {
      updateCard(provider.id, { error: (failed as { ok: boolean; error?: string }).error ?? 'Unknown error.' });
      return;
    }

    updateCard(provider.id, { saved: true, inputValue: '' });
    if (provider.secondaryField) {
      updateCard(provider.secondaryField.id, { inputValue: '' });
    }
    await fetchStatus();
    setTimeout(() => {
      updateCard(provider.id, { saved: false });
    }, 3000);
  }

  if (!backendOnline) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="wb-card px-6 py-8 text-center max-w-md">
          <div className="w-10 h-10 rounded-xl bg-raised flex items-center justify-center mx-auto mb-3">
            <svg className="w-5 h-5 text-fg-4" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01" />
            </svg>
          </div>
          <p className="text-fg-2 font-semibold text-sm">Backend is offline</p>
          <p className="text-fg-3 text-xs mt-1">Start the backend to manage API keys.</p>
        </div>
      </div>
    );
  }

  const configuredCount = keyStatus
    ? PROVIDERS.filter(p => keyStatus[p.id]).length
    : 0;

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="wb-card p-5">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div>
            <p className="text-xs text-fg-3 mt-0.5">
              {keyStatus !== null
                ? `${configuredCount} of ${PROVIDERS.length} providers configured`
                : 'Configure third-party enrichment provider credentials.'}
            </p>
          </div>
          <button
            onClick={() => void fetchStatus()}
            disabled={loading}
            className="shrink-0 text-xs px-3 py-1.5 rounded-lg bg-surface border border-line-strong text-fg-2 font-medium hover:bg-inset transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Refreshing…' : 'Refresh status'}
          </button>
        </div>

        {/* Storage notice */}
        <div className="bg-warn-bg border border-warn-line rounded-lg px-3 py-2.5 text-xs text-warn-fg flex items-start gap-2">
          <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <span>
            API keys are stored in{' '}
            <code className="bg-warn-bg border border-warn-line text-warn-fg px-1 py-0.5 rounded font-mono text-[11px]">
              backend/.env
            </code>{' '}
            on your local machine only. They are never sent to the frontend or logged.
          </span>
        </div>
      </div>

      {/* Provider cards */}
      <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))' }}>
        {PROVIDERS.map(provider => {
          const state = cardState[provider.id] ?? makeDefaultCardState();
          const isConfigured = keyStatus ? (keyStatus[provider.id] ?? false) : false;
          const hasInput = state.inputValue.trim().length > 0;

          return (
            <div key={provider.id} className="wb-card p-4 flex flex-col gap-3">
              {/* Card header */}
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="text-[13px] font-semibold text-fg-1">{provider.name}</h3>
                  <p className="text-xs text-fg-3 mt-0.5 leading-relaxed">{provider.description}</p>
                </div>
                {keyStatus !== null && <StatusBadge configured={isConfigured} />}
              </div>

              {/* Supported IOC types */}
              <div className="flex flex-wrap gap-1">
                {provider.supports.map(s => (
                  <span
                    key={s}
                    className="text-[11px] px-1.5 py-0.5 rounded font-mono bg-raised text-fg-2 border border-line"
                  >
                    {s}
                  </span>
                ))}
              </div>

              {/* Tier */}
              <p className="text-xs text-fg-3">{provider.tier}</p>

              {/* Optional note */}
              {provider.note && (
                <div className="bg-warn-bg border border-warn-line rounded-lg px-2.5 py-2 text-xs text-warn-fg leading-relaxed">
                  {provider.note}
                </div>
              )}

              {/* Sign up link */}
              <a
                href={provider.signupUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-accent-fg hover:text-accent-fg font-medium self-start transition-colors flex items-center gap-1"
              >
                Sign up / get API key
                <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6m4-3h6v6m-11 5L21 3" />
                </svg>
              </a>

              {/* Input row(s) */}
              <div className="flex flex-col gap-2 mt-auto pt-1 border-t border-line-soft">
                {provider.secondaryField ? (
                  <>
                    <div>
                      <label className="block text-[11px] font-semibold uppercase tracking-wider text-fg-4 mb-1">
                        API ID
                      </label>
                      <input
                        type="password"
                        placeholder="Paste API ID…"
                        value={state.inputValue}
                        onChange={e => updateCard(provider.id, { inputValue: e.target.value, error: null, saved: false })}
                        onKeyDown={e => { if (e.key === 'Enter') void handleSave(provider); }}
                        className="w-full bg-surface border border-line rounded-lg px-2.5 py-2 text-xs text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-colors"
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-semibold uppercase tracking-wider text-fg-4 mb-1">
                        API Secret
                      </label>
                      <input
                        type="password"
                        placeholder="Paste API Secret…"
                        value={cardState[provider.secondaryField.id]?.inputValue ?? ''}
                        onChange={e => updateCard(provider.secondaryField!.id, { inputValue: e.target.value, error: null, saved: false })}
                        onKeyDown={e => { if (e.key === 'Enter') void handleSave(provider); }}
                        className="w-full bg-surface border border-line rounded-lg px-2.5 py-2 text-xs text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-colors"
                        autoComplete="off"
                      />
                    </div>
                    <button
                      onClick={() => void handleSave(provider)}
                      disabled={state.saving || !hasInput}
                      className={`self-end text-xs px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1.5 ${
                        state.saved
                          ? 'bg-ok-bg border border-ok-line text-ok-fg'
                          : hasInput && !state.saving
                          ? 'bg-accent hover:bg-accent-strong text-white border border-accent'
                          : 'bg-raised text-fg-4 border border-line cursor-not-allowed'
                      }`}
                    >
                      {state.saving ? (
                        <span>Saving…</span>
                      ) : state.saved ? (
                        <>
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                          <span>Saved</span>
                        </>
                      ) : (
                        <span>Save both</span>
                      )}
                    </button>
                  </>
                ) : (
                  <div className="flex gap-2">
                    <input
                      type="password"
                      placeholder="Paste key here…"
                      value={state.inputValue}
                      onChange={e => updateCard(provider.id, { inputValue: e.target.value, error: null, saved: false })}
                      onKeyDown={e => { if (e.key === 'Enter') void handleSave(provider); }}
                      className="flex-1 min-w-0 bg-surface border border-line rounded-lg px-2.5 py-2 text-xs text-fg-1 placeholder-fg-4 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-colors"
                      autoComplete="off"
                    />
                    <button
                      onClick={() => void handleSave(provider)}
                      disabled={state.saving || !hasInput}
                      className={`shrink-0 text-xs px-3 py-2 rounded-lg font-medium transition-colors flex items-center gap-1.5 ${
                        state.saved
                          ? 'bg-ok-bg border border-ok-line text-ok-fg'
                          : hasInput && !state.saving
                          ? 'bg-accent hover:bg-accent-strong text-white border border-accent'
                          : 'bg-raised text-fg-4 border border-line cursor-not-allowed'
                      }`}
                    >
                      {state.saving ? (
                        <span>Saving…</span>
                      ) : state.saved ? (
                        <>
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                          <span>Saved</span>
                        </>
                      ) : (
                        <span>Save</span>
                      )}
                    </button>
                  </div>
                )}
              </div>

              {/* Inline error */}
              {state.error && (
                <p className="text-xs text-danger-fg flex items-center gap-1">
                  <svg className="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                  </svg>
                  {state.error}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
