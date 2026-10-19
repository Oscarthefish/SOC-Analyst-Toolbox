# SOC Analyst Toolbox

A local workbench for SOC analysts. Paste an indicator (IP, domain, URL, hash, email, ASN, CIDR or raw email headers) to:

- classify and normalise it, including refanging defanged input such as `hxxps://evil[.]com`
- enrich it across threat-intel providers through a local backend, then get a severity verdict, flags where providers contradict each other, and an optional summary from a local LLM
- pivot to 60 external investigation tools, each pre-filled with the indicator and labelled with how much it exposes it

The browser talks only to a backend on your own machine. API keys stay in `backend/.env` and never reach the browser. There is no telemetry.

---

## Quick start

Requires Node.js 20 or later.

```bash
npm install
npm run backend:install
cp backend/.env.example backend/.env   # add whichever API keys you have
npm run dev                            # frontend on :5173, backend on :8787
```

Open <http://localhost:5173>.

- **Without any API keys**, enrichment still works from keyless sources: DNS, crt.sh, the Wayback Machine, the Tor exit list, WHOIS/RDAP, BGPView, CISA KEV, Ransomware.live and others. Pivot links always work.
- **Without the backend running**, classification, pivot tools, bulk extraction and defang/refang still work. Analysis is disabled and the sidebar shows **Backend offline**.
- **Optional LLM summary:** install [Ollama](https://ollama.com) and run `ollama pull qwen2.5`. If Ollama isn't running, analysis still returns provider results and a computed verdict, just without the written narrative.

| Command | What it does |
|---|---|
| `npm run dev` | Frontend and backend together |
| `npm run frontend:dev` | Frontend only |
| `npm run backend:dev` | Backend only (port 8787) |
| `npm run build` | Typecheck and build the frontend to `dist/` |
| `npm run backend:build` | Build the backend to `backend/dist/` |
| `npm run lint` | ESLint |
| `npm test` / `npm run backend:test` | Frontend / backend unit tests (Vitest) |
| `npm run check` | Lint, typecheck and test both packages (what CI runs, minus the build) |

---

## Pages

| Page | What it's for |
|---|---|
| **Investigate** | Enter one indicator, optionally pick a workflow, run analysis, and open pivot tools. Results lead with the computed severity and next steps; the local LLM summary follows, labelled as such. The **Case** panel records your verdict, confidence, actions taken and notes, and shows the workflow's checklist and pre-filled internal SIEM/EDR queries. Shortcuts: `/` focuses the input, ⌘/Ctrl+Enter runs analysis, Esc clears it, ⌘/Ctrl+S saves the case. |
| **Hunt** | Build hunting queries for **Microsoft Sentinel** (KQL), **Defender XDR advanced hunting** (KQL) or **Splunk** (SPL). Indicators give *sweeps* (where has this appeared in our logs?); MITRE ATT&CK techniques give *hunts* (is this behaviour happening anywhere?). Pick techniques from an ATT&CK matrix, choose a look-back, copy the query. See [Hunting and ATT&CK](#hunting-and-attck). |
| **Cases** | Saved investigations, stored in this browser. Filter open/closed, search, reopen a case with its indicator, workflow and analysis restored, or export it as Markdown or JSON. |
| **Bulk extract** | Paste logs, alerts or email bodies and extract every indicator. Send any of them to Investigate, or all of them to Hunt. |
| **Batch triage** | Enrich up to 50 indicators (5 at a time), then sort and filter by severity and export as CSV. |
| **Threat feed** | Recently exploited CVEs (CISA KEV), ransomware activity and Pulsedive high-risk infrastructure. |
| **History** | Your last analyses, stored in this browser. Reload one without calling the providers again. |
| **Defang / refang** | Convert indicators between live and safe-to-share forms. |
| **Integrations** | Set provider API keys. They're written to `backend/.env`. |
| **Tool library** | Hide built-in pivot tools, or add your own internal ones (SIEM, EDR, ticketing). |
| **Template check** | Validate every tool's URL template against sample indicators. No network requests are made. |

Press **⌘K / Ctrl+K** anywhere to jump to a page, an open case or a recent indicator, or type an indicator to investigate it.

Light and dark themes follow your OS setting. You can override that in the sidebar. Both themes meet WCAG AA contrast and pass an axe-core audit.

---

## Hunting and ATT&CK

Every analysis lists the MITRE ATT&CK techniques linked to the indicator, with the evidence for each:

| Evidence | Where it comes from |
|---|---|
| **Reported** | The provider lists the technique against the indicator: AlienVault OTX pulse `attack_ids` and Hybrid Analysis sandbox reports. |
| **Inferred** | A provider label maps to a technique, e.g. GreyNoise *SSH Bruteforcer* → T1110 Brute Force and T1021.004 SSH, *Tor* → T1090.003 Multi-hop Proxy, ThreatFox `botnet_cc` → T1071. The matching label is shown. |
| **Workflow context** | The chosen workflow is about that activity, e.g. URL / Phishing → T1566.002 Spearphishing Link. |

**Build hunt queries** opens the Hunt page with the indicator and techniques filled in. Queries are templates in `src/data/huntQueries.ts`:

- **KQL** follows the [Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries) style (time filter first, `summarize … by`). Sentinel uses `TimeGenerated`; Defender XDR uses `Timestamp` and its own tables. Queries are only offered on platforms where their tables exist.
- **SPL** uses CIM field names. Base searches default to CIM tags (`index=* tag=network tag=communicate`, …); set your own index and sourcetype per data source on the Hunt page to make them faster. The Tor hunt needs a `tor_exit_nodes` lookup.
- Treat them as starting points: check table and field names against your environment and tune thresholds before scheduling any as a detection.

To add a query, append to `HUNT_TEMPLATES` with its techniques, platforms, source table and what to look for. A test renders every template on every platform and fails if a placeholder is left unfilled or a technique isn't in `src/data/attack.ts`.

---

## Enrichment providers

Add keys in **Integrations** or directly in `backend/.env`:

| Variable | Provider | Used for |
|---|---|---|
| `GREYNOISE_API_KEY` | GreyNoise | IPs |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IPs |
| `IPINFO_TOKEN` | IPinfo | IPs |
| `VIRUSTOTAL_API_KEY` | VirusTotal | IPs, domains, URLs, hashes |
| `URLSCAN_API_KEY` | urlscan.io | Domains, URLs (search works without a key) |
| `SHODAN_API_KEY` | Shodan | IPs |
| `CENSYS_API_TOKEN` | Censys | IPs |
| `WHOISXMLAPI_KEY` | WhoisXML API | Domains, IPs |
| `OTX_API_KEY` | AlienVault OTX | Most types |
| `PULSEDIVE_API_KEY` | Pulsedive | Most types, Threat feed |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing | Domains, URLs |
| `HIBP_API_KEY` | Have I Been Pwned | Emails |
| `HYBRID_ANALYSIS_KEY` | Hybrid Analysis | Hashes |
| `THREATFOX_API_KEY` | ThreatFox | Most types |
| `URLHAUS_API_KEY` | URLhaus | Domains, URLs |
| `HUNTER_API_KEY` | Hunter.io | Domains, emails (opt-in per run; uses credits) |
| `DNSDUMPSTER_API_KEY` | DNSDumpster | Domains |
| `IPAPI_KEY` | ip-api.com Pro | IPs (HTTPS). The free tier is plain HTTP, so ip-api is off unless you set this or `IPAPI_ALLOW_HTTP=true` |

Other settings in `backend/.env`:

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | Backend port |
| `CACHE_TTL_MINUTES` | `60` | How long provider results are cached |
| `ENABLE_URL_SUBMISSION` | `false` | Allow submitting new urlscan.io scans (they're public by default) |
| `ENABLE_HIGH_RISK_ENRICHMENT` | `false` | Allow the credential validator (see below) |
| `ALLOWED_ORIGINS` | Vite dev and preview on localhost | Comma-separated frontend origins allowed to call the API |
| `RATE_LIMIT_<PROVIDER>` | Free-tier limits for VirusTotal (4), ip-api (45), Shodan (60), HIBP (10) | Requests per minute for a provider, e.g. `RATE_LIMIT_VIRUSTOTAL=500` for a premium key. `0` disables the limit |
| `CACHE_DIR` | `.cache/` at the repo root | Where the enrichment cache is stored |

---

## Safety model

- **Exposure labels on pivot tools.** **Passive** tools are lookups only. **Submits IOC** tools send the indicator to the service, which may log it. **Public** tools make it visible to others (live scans, shared sandboxes). If the indicator is a URL containing tokens or identifiers, the Open button for non-passive tools turns amber.
- **Nothing runs automatically.** Enrichment only runs when you click **Run analysis**.
- **Lookups only.** VirusTotal and the other providers are never sent files, and URLs are never submitted for scanning unless `ENABLE_URL_SUBMISSION=true`.
- **The backend accepts local requests only.** It binds to `127.0.0.1` and rejects any request whose `Host` header isn't `localhost`/`127.0.0.1`, which blocks DNS-rebinding attacks. It also rejects browser requests from any origin not in `ALLOWED_ORIGINS`.
- **Credential validator is off by default.** The `credvalidate` provider checks whether a leaked token is live by calling the issuing service. It only runs when `ENABLE_HIGH_RISK_ENRICHMENT=true` **and** the request sets `options.allowCredentialValidation: true`. Its results are never cached.
- **What gets cached.** Results are stored in `.cache/enrichment-cache.json` at the repo root, which is gitignored. URL and secret indicators are hashed in cache keys, so raw values are never written to disk.
- **Custom tools are validated.** Their URLs must be `http(s)`. Anything else is rejected when saving and never rendered as a link.
- **Browser storage isn't encrypted.** Cases, history and preferences live in `localStorage`, so don't use this on a shared machine for sensitive cases. The About page lists what's stored and can clear it.
- **Outbound requests have a hard deadline.** Every provider request is capped at 30 s including the response body, so a stalled provider can't hang an analysis.

Always follow your organisation's policy on sharing indicators with external services.

---

## Customising tools and workflows

**Custom tools.** Add them on the **Tool library** page. They're saved to `backend/data/customTools.json`, which is gitignored. `src/data/customTools.example.json` shows the format, with templates for Splunk, Cortex XDR, Mimecast, Palo Alto and Jira.

**Built-in tools** live in `src/data/tools.json`:

```json
{
  "id": "unique-tool-id",
  "name": "Tool Name",
  "category": "Category Label",
  "description": "Short description.",
  "inputTypes": ["ipv4", "domain"],
  "workflows": ["ip-triage", "domain-triage"],
  "urlTemplate": "https://example.com/lookup/{{ip}}",
  "whyUse": "Why an analyst would use this tool.",
  "lookFor": "What to look for in the results.",
  "riskNote": "Privacy or submission notes.",
  "submissionRisk": "low",
  "requiresAccount": "none",
  "tags": ["reputation"]
}
```

- `inputTypes`: `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email`, `asn`, `cidr`
- `submissionRisk`: `low` (Passive), `medium` (Submits IOC), `high` (Public)
- `requiresAccount`: `none`, `free_account`, `trial`, `paid`, `mixed`

URL template variables:

| Variable | Resolves to |
|---|---|
| `{{value}}` / `{{encodedValue}}` | Normalised indicator (raw / URL-encoded) |
| `{{ip}}` / `{{encodedIp}}` | IP address |
| `{{domain}}` / `{{encodedDomain}}` | Domain, or the URL's hostname |
| `{{url}}` / `{{encodedUrl}}` | Full URL |
| `{{hash}}` | File hash |
| `{{email}}` / `{{encodedEmail}}` | Email address |
| `{{asn}}`, `{{cidr}}` | ASN, CIDR |
| `{{encodedQuery}}` | Best search value, URL-encoded |

If a template still contains an unfilled variable for the current indicator type, the tool is marked **manual**: open it and paste the indicator in yourself.

**Workflows** live in `src/data/workflows.json`. Each one lists the indicator types it accepts (`allowedInputTypes`), its pivot tools (`toolIds`), an analyst checklist and internal search templates. Tool ids that don't exist are skipped.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Sidebar shows **Backend offline** | Run `npm run backend:dev`, or `npm run dev` |
| `403 Forbidden origin` | You're calling the backend directly from a page on a port that isn't allowed. Use the Vite dev or preview server, which proxies `/api`, or add the origin to `ALLOWED_ORIGINS` in `backend/.env` |
| Backend not on port 8787 | Start Vite with `BACKEND_PORT=<port>` so the `/api` proxy points at it |
| Provider shows **No key** | Add the key in Integrations, or in `.env` and restart the backend |
| Provider shows **Rate limited** | The provider hit its per-minute limit or returned a 429; the result says when to retry. Raise the limit with `RATE_LIMIT_<PROVIDER>` if your plan allows more |
| No written summary | Start Ollama and pull a model (`ollama pull qwen2.5`) |

## Known limitations

- Domain extraction uses a TLD allowlist, so very new TLDs may be missed.
- IPv6 addresses aren't defanged.
- One indicator is analysed at a time on Investigate. Use Batch triage for lists.

See `docs/REVIEW.md` for the current review and roadmap.
