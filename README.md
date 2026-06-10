# SOC Analyst Toolbox

A local-first web app for SOC analysts. Paste an IOC (IP, domain, URL, hash, email, ASN, or CIDR), select an investigation workflow, and get pre-populated links to external investigation tools, analyst checklists, internal search suggestions, a generated case note template, verdicts, and saved cases.

**Runs entirely in your browser. No backend. No API calls. No telemetry.**

---

## What it does

### Phase 1 (original)
- Detects and normalises IOC type (IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, email, ASN, CIDR)
- Warns when a URL contains sensitive tokens or identifiers
- Shows relevant investigation workflows for the detected IOC type
- Generates pre-populated links to 40+ external investigation tools
- Displays submission risk badges (Low / Medium / High) and access type for each tool
- Provides a workflow-specific analyst checklist with progress tracking
- Shows internal search query templates for SIEM, EDR, firewall, proxy, and other tools
- Auto-generates a markdown case note template you can copy and paste into your ticketing system

### Phase 3 (new — optional local backend)
- **API enrichment** — GreyNoise, AbuseIPDB, IPinfo, VirusTotal, urlscan.io, Shodan, Censys
- **Local backend** — Express server on `localhost:8787`; all API keys stay in `backend/.env`, never in the browser
- **Caching** — file-based cache with configurable TTL
- **Safety controls** — no file upload, no URL submission by default, sensitive URL detection
- **Enrichment in case notes** — API results included in exported markdown and JSON

### Phase 1.5 / Phase 2 foundation
- **Bulk IOC extraction** — paste arbitrary log text and extract all IOCs at once
- **Defang / refang** — convert IOCs between live and safe-for-sharing formats
- **Saved cases** — save and restore investigations to localStorage
- **Assessment / verdict** — record verdict, confidence, and recommended actions
- **Enhanced export** — copy analyst pack (fanged or defanged), export as .md or .json
- **Custom tools** — add your internal tools (Splunk, XDR, Jira, etc.)
- **Config Check** — validate all tool URL templates against sample IOCs

---

## Install

```bash
npm install
```

## Run (development)

```bash
npm run dev
```

The app will be available at `http://localhost:5173` (or the next available port).

## Build (production)

```bash
npm run build
```

Output goes to `dist/`. You can serve it with any static file server:

```bash
npm run preview
```

---

## Navigation tabs

| Tab | Description |
|---|---|
| **Single IOC** | Original Phase 1 investigation workflow. Enter one IOC, pick a workflow, get tools and checklists. |
| **Bulk Extract** | Paste any text (logs, emails, alerts) to extract all IOCs at once. Click "Investigate" to send any IOC to the Single IOC tab. |
| **Defang / Refang** | Convert IPs, domains, and URLs between fanged (live) and defanged (safe-to-share) formats. |
| **Cases** | Save the current investigation to localStorage. Load, edit, export, or delete saved cases. |
| **Config Check** | Validate tool URL templates against sample IOCs. Shows which tools support which IOC types. |

---

## Bulk IOC extraction

1. Go to the **Bulk Extract** tab.
2. Paste any text: email headers, firewall logs, EDR alerts, proxy logs, SIEM search results.
3. Click **Extract IOCs**.
4. Results appear in a table with type, normalised value, and suggested workflows.
5. Use the filter buttons to view only IPs, domains, hashes, etc.
6. Click **Copy** to copy a single IOC, **Investigate** to send it to the Single IOC tab.
7. Click **Copy all IOCs** or **Copy CSV** to export all results at once.

Extracted types: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, email, ASN, CIDR.

False-positive reduction is applied:
- Dotted strings are only treated as domains if the TLD is in a known valid TLD list.
- Version strings (e.g. `1.0.0`, `2.3.1`) are excluded.
- Strings ending in file extensions (`.exe`, `.dll`, `.pdf`, etc.) are excluded.
- Strings already matched as IPs or emails are not re-matched as domains.

---

## Saved cases

1. Investigate an IOC in the **Single IOC** tab.
2. Switch to the **Cases** tab and click **+ New case**.
3. Optionally set a title and ticket reference. Click **Save case**.
4. The case stores: IOC, workflow, checklist state, assessment, and notes.
5. Load a case back into Single IOC by clicking **Load into Single IOC**.
6. Export a case as `.md` or `.json` using the export buttons.
7. Delete a case with the **Delete** button.

Cases are stored in `localStorage` under key `soc_toolbox_cases_v1`. They persist between sessions until manually deleted or localStorage is cleared.

---

## Defang / refang usage

Go to the **Defang / Refang** tab and type or paste any IOC.

The type is auto-detected and both defanged and refanged versions are shown with copy buttons.

| Input | Defanged output |
|---|---|
| `1.2.3.4` | `1[.]2[.]3[.]4` |
| `example.com` | `example[.]com` |
| `https://example.com/path` | `hxxps://example[.]com/path` |
| `http://example.com/path` | `hxxp://example[.]com/path` |

You can also paste already-defanged values (e.g. `hxxps://evil[.]example[.]com`) and the refanged form will be shown.

---

## Assessment / verdict

In the **Single IOC** tab, the **Assessment** panel lets you:

- Select a verdict: Benign, Known scanner/noise, Suspicious, Likely malicious, Confirmed malicious, Inconclusive
- Set confidence: Low, Medium, High
- Multi-select recommended actions (Block, Quarantine, Isolate endpoint, Reset password, etc.)
- Get an auto-generated assessment summary paragraph

The assessment is included when you save a case or export the analyst pack.

---

## Custom tools

You can add internal tools (Splunk, Cortex XDR, Mimecast, Palo Alto, Jira, etc.) using a local `customTools.json` file.

### Setup

1. Copy the example file:
   ```bash
   cp src/data/customTools.example.json src/data/customTools.json
   ```

2. Edit `src/data/customTools.json` with your real internal URLs.

3. Rebuild or restart dev server (`npm run dev`).

The example file includes templates for:
- Splunk IP search
- Splunk domain search
- Cortex XDR IP search
- Cortex XDR hash search
- Mimecast message trace
- Palo Alto traffic log search
- Jira search

Custom tools use the same format as built-in tools (see `src/data/tools.json`). They are merged with built-in tools and appear in:
- The Tool Panel (when a matching workflow is selected)
- The Config Check tab (with a "custom" badge)
- The count shown in Config Check

`customTools.json` is excluded from version control (add it to `.gitignore`). The example file is safe to commit.

---

## Enhanced copy / export

In the **Single IOC** tab, the **Analyst Pack / Case Note** panel provides:

| Button | What it copies/downloads |
|---|---|
| **Copy tool links (MD)** | Markdown list of all tool names and links for the current IOC |
| **Copy analyst pack** | Full investigation note as markdown (IOC, workflow, tools, checklist, assessment) |
| **Copy defanged pack** | Same but with the IOC defanged (safe for ticket systems) |
| **Export .md** | Downloads the analyst pack as a `.md` file |
| **Export .json** | Downloads a structured JSON export of the investigation |

---

## Privacy warning

Many of the linked tools are public services. Before clicking **Open** on any tool card:

- Check the **submission risk badge** (Low / Medium / High).
- High-risk tools may make your IOC public, take live screenshots of URLs, or submit samples to shared sandboxes.
- Sensitive URLs (containing tokens, session IDs, auth codes, etc.) are flagged with a warning. Do not submit these to public tools.
- Internal hostnames, internal IPs, and unreleased sample hashes should be treated as sensitive.
- Always follow your organisation's SOC policy on external tool usage.
- The **Defang / refang** feature helps you share IOCs in tickets without creating accidental clickable links.

**Saved cases are stored in your browser's localStorage.** They are not encrypted. Do not save highly sensitive data (password hashes, live auth tokens, etc.) as case notes if your machine is shared or untrusted.

---

## Config Check tab

The Config Check tab shows all configured tools (built-in + custom) and validates each tool's URL template against seven sample IOCs:

| Sample | IOC |
|---|---|
| IPv4 | `8.8.8.8` |
| Domain | `example.com` |
| URL | `https://login.example.com/reset?token=abc` |
| SHA256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Email | `user@example.com` |
| ASN | `AS15169` |
| CIDR | `192.168.1.0/24` |

Status indicators:
- **Green tick (✓)** — URL renders correctly for this IOC type (clicking opens the tool with the sample)
- **Amber dash (—)** — Home URL or no template vars (manual lookup required)
- **Red X (✗)** — Template still contains unfilled placeholders for this IOC type (configuration problem)
- **Dot (·)** — IOC type not in the tool's `inputTypes` list (expected — not a problem)

No network requests are made by Config Check.

---

## How to add a new built-in tool

Edit `src/data/tools.json`. Each tool entry uses this structure:

```json
{
  "id": "unique-tool-id",
  "name": "Tool Name",
  "category": "Category Label",
  "description": "Short description shown in the card.",
  "inputTypes": ["ipv4", "domain"],
  "workflows": ["ip-triage", "domain-triage"],
  "urlTemplate": "https://example.com/lookup/{{ip}}",
  "whyUse": "Why an analyst would use this tool.",
  "lookFor": "What indicators to look for in the results.",
  "riskNote": "Any privacy or submission risk notes.",
  "submissionRisk": "low",
  "requiresAccount": "none",
  "tags": ["reputation", "ip"]
}
```

**Supported inputTypes values:**
`ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email`, `asn`, `cidr`

**Supported submissionRisk values:**
`low`, `medium`, `high`

**Supported requiresAccount values:**
`none`, `free_account`, `trial`, `paid`, `mixed`

**URL template variables:**

| Variable | Resolves to |
|---|---|
| `{{value}}` | Normalised IOC value |
| `{{encodedValue}}` | URL-encoded normalised value |
| `{{ip}}` | IP address (IPv4/IPv6) |
| `{{domain}}` | Domain or URL hostname |
| `{{url}}` | Full URL |
| `{{hash}}` | File hash |
| `{{email}}` | Email address |
| `{{asn}}` | ASN string |
| `{{cidr}}` | CIDR string |
| `{{encodedQuery}}` | Best search value, URL-encoded |

If a template variable is empty for the current IOC type, the card shows "Open Home" instead of a pre-filled link.

---

## Known limitations

- **Bulk extraction false positives:** Domain extraction uses a TLD allowlist. Very new or unusual TLDs may be missed. Version strings and file extensions are excluded by heuristic — edge cases may still slip through.
- **Defang/refang edge cases:** IPv6 defanging is not currently applied (colons are not replaced). Very unusual URL schemes are not handled.
- **Case checklist restore:** When loading a saved case, the checklist is only restored if the same workflow is still present. If the workflow has changed or been removed from `workflows.json`, checklist state may not apply correctly.
- **Custom tools dynamic import:** In production builds, `customTools.json` must exist at the time of the build. Hot reloading of custom tools after the initial dev server start requires a page reload.
- **No encryption:** localStorage data is not encrypted. Treat it as developer/analyst-grade local storage only.
- **No multi-IOC workflow:** The Single IOC tab handles one IOC at a time. Use Bulk Extract + individual Investigate buttons for multi-IOC workflows.

---

## How to add a new workflow

Edit `src/data/workflows.json`. Each workflow uses this structure:

```json
{
  "id": "unique-workflow-id",
  "name": "Workflow Name",
  "description": "Short description.",
  "allowedInputTypes": ["ipv4", "ipv6"],
  "toolIds": ["greynoise-ip", "abuseipdb"],
  "checklist": [
    "Is the IP flagged by multiple sources?",
    "Is it a known VPN or Tor exit node?"
  ],
  "internalSearches": [
    { "label": "Firewall", "template": "src_ip={{value}}" },
    { "label": "EDR", "template": "remote_ip={{value}}" }
  ],
  "expectedOutcome": "Determine if the IP is malicious, noise, or benign."
}
```

`toolIds` must match `id` values in `tools.json`. Tools not found in the tools file are silently skipped.

---

## Phase 3 — Local API Enrichment Backend

Phase 3 adds an optional local Express backend that routes API calls to enrichment providers. API keys are stored only in `backend/.env` and never reach the browser.

### Architecture

```
Browser (React) → Local backend (localhost:8787) → External APIs
```

The frontend never holds API keys. The backend performs all API calls, caches results, and returns structured enrichment data to the frontend.

### Backend setup

```bash
# 1. Install backend dependencies
npm run backend:install

# 2. Copy the example env file
cp backend/.env.example backend/.env

# 3. Add your API keys to backend/.env
# (See "Provider key setup" below)
```

### Running

| Command | What it does |
|---|---|
| `npm run frontend:dev` | Frontend only (no API enrichment) |
| `npm run backend:dev` | Backend only (port 8787) |
| `npm run dev` | Both frontend and backend concurrently |
| `npm run backend:build` | Build backend to `backend/dist/` |

### Provider key setup

| Provider | Where to get the key | IOC types |
|---|---|---|
| **GreyNoise** | [greynoise.io](https://greynoise.io) — free community API available | IPv4, IPv6 |
| **AbuseIPDB** | [abuseipdb.com](https://www.abuseipdb.com) — free tier available | IPv4, IPv6 |
| **IPinfo** | [ipinfo.io](https://ipinfo.io) — free tier (50k req/month) | IPv4, IPv6 |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com) — free API key available | IPv4, IPv6, domain, MD5, SHA1, SHA256 |
| **urlscan.io** | [urlscan.io](https://urlscan.io) — optional for search; anonymous search also works | domain, URL (search only), IPv4 |
| **Shodan** | [shodan.io](https://shodan.io) — paid plan required for host lookup API | IPv4 |
| **Censys** | [search.censys.io](https://search.censys.io) — account required; API access depends on plan | IPv4, IPv6 |

Add keys to `backend/.env`:

```env
GREYNOISE_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
IPINFO_TOKEN=your_token_here
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here   # optional for search
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
```

### Safety model

- **VirusTotal**: Lookup only. No file upload, no URL submission, no URL ID computation.
- **urlscan.io**: Search only by default. New scans are never submitted unless `ENABLE_URL_SUBMISSION=true` in `.env` AND the user enables the option in the UI.
- **Shodan / Censys**: Exposure data only. Open ports shown do not indicate compromise.
- **Sensitive URLs**: URLs with tokens/session IDs/auth codes can be blocked from lookup. The UI provides a checkbox to allow lookups on sensitive URLs — disabled by default.
- **No automatic calls**: Enrichment only runs when the analyst clicks "Run Enrichment". The backend is never called automatically.

### Caching behaviour

Results are cached in `backend/.cache/enrichment-cache.json`:

- Default TTL: 60 minutes (configurable via `CACHE_TTL_MINUTES` in `.env`)
- Cache key: `{provider}:{iocType}:{normalisedIoc}` (for URLs, the IOC portion is SHA256-hashed)
- Use "Refresh (bypass cache)" in the UI to force a fresh lookup
- The cache directory is gitignored

### Troubleshooting

| Problem | Solution |
|---|---|
| "Enrichment backend is offline" banner | Run `npm run backend:dev` or `npm run dev` |
| Provider shows "No key" | Add the API key to `backend/.env` and restart the backend |
| Provider shows "Rate limited" | Wait 60 seconds; the backend tracks rate limits per provider |
| CORS error in browser console | Ensure the backend is running on port 8787 and the frontend on 5173 or 5174 |
| Censys returns 401/403 | Your Censys plan may not include API access; check your plan at search.censys.io |
| Shodan returns 404 for a valid IP | The IP may not be in Shodan's dataset; this is normal for private/RFC1918 IPs |

---

## Phase 4 ideas (future)

- **VirusTotal URL scanning** — analyst-confirmed opt-in URL submission with explicit consent dialog
- **MISP integration** — look up IOCs against a self-hosted MISP instance
- **Automated ticket creation** — push enrichment results to Jira/ServiceNow via local credentials
- **MITRE ATT&CK tagging** — map workflow steps and findings to ATT&CK techniques
- **Email .eml parser** — drag-and-drop `.eml` file support with automated header extraction
- **Network graph** — visualise IOC relationships (domain → IP, IP → ASN, etc.)
- **YARA rule hints** — generate skeleton YARA rules from hash/string context
- **Custom workflow editor** — UI to create and edit workflows without editing JSON
- **Export to PDF** — generate formatted investigation reports
