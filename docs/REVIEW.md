# SOC Analyst Toolbox: review and optimisation plan

_Reviewed 2026-10-19 at commit `f410793`._

## Summary

The core is solid. IOC detection and normalisation work well, the adapter layer is clean (30 providers behind one `AdapterFn` contract), and the contradiction and VPN/Tor heuristics in `routes/analyse.ts` add real analyst value. Lint and both typechecks pass.

The main weaknesses:

1. **Security posture of the local backend.** It has no authentication and no Host checks, it writes `.env` and tool config from HTTP, and secrets were leaking into the cache file (fixed in this pass).
2. **No tests at all**, around detection and scoring logic that analysts will rely on to make decisions.
3. **UI built from one-off hex values.** There were about 1,200 hardcoded colour classes, and dark mode was a list of CSS overrides that matched those hex values. This is the main reason the app looked templated. Most of it was addressed in this pass (see "UI changes made" below).
4. **Documentation drift.** The README describes a "Cases" tab, an Assessment panel and "No backend. No API calls." None of that matches the current app.

---

## 1. Security findings

| # | Severity | Finding | Location | Recommendation |
|---|---|---|---|---|
| S1 | **High** (fixed) | Values checked by the credential validator were written in plaintext into the on-disk cache key (`credvalidate:secret:<raw secret>`). This contradicts the adapter's own "no credential value is stored" claim. | `backend/src/cache.ts` | Fixed: secrets are now hashed like URLs. **Delete any existing `.cache/enrichment-cache.json`.** Better still, never cache `secret` results at all. |
| S2 | High (fixed) | The credential validator runs by default for the `secret` type (`DEFAULT_PROVIDERS.secret = ['credvalidate']`). The docstring says it must be requested explicitly. It sends found credentials to vendor APIs. | `routes/enrich.ts:54` | Gate it behind `ENABLE_HIGH_RISK_ENRICHMENT=true` and an explicit per-request opt-in. |
| S3 | High (fixed) | The backend has no auth and no Host/Origin enforcement. CORS stops browsers from *reading* responses, but DNS-rebinding pages can still reach `127.0.0.1:8787`. Any local process can rewrite `.env` keys (`POST /api/config/keys`), overwrite tool config (`PUT /api/tools/custom`) and spend API quota. | `server.ts`, `routes/keys.ts`, `routes/toolsConfig.ts` | Reject requests whose `Host` is not `localhost`/`127.0.0.1:<port>`. Require a per-launch random token (printed at startup, sent as a header). Require `Origin` on mutating routes. |
| S4 | Medium (fixed) | `PUT /api/tools/custom` accepts any JSON array. `urlTemplate` is rendered straight into `<a href>`, so a `javascript:` template becomes stored XSS. | `toolsConfig.ts`, `ToolCard.tsx`, `ConfigCheckPanel.tsx` | Validate the schema server-side and allow only `https?:` URLs. Also check the scheme client-side before rendering `href`. |
| S5 | Medium (fixed) | 5 known-vulnerable backend dependencies (1 critical, `proxy-addr`; also `qs`, `body-parser`, `esbuild`). The lockfile wasn't refreshed by the "remediate dependencies" commit. | `backend/package-lock.json` | `cd backend && npm audit fix`, then plan an Express 5 upgrade. Drop `node-fetch` because Node 18+ has `fetch` built in. |
| S6 | Medium | ip-api.com is called over plain HTTP, so indicators cross the network in cleartext. | `adapters/ipapi.ts:58` | Make it opt-in, use the paid HTTPS endpoint, or remove it (IPinfo covers the same data). |
| S7 | Low | The frontend loaded IBM Plex from Google Fonts, an external request from a "no telemetry" tool. | `index.html` | Fixed: fonts are now self-hosted via `@fontsource`. |
| S8 | Low | `.env` writes aren't atomic, and the key endpoint trims values inconsistently between read and write. | `routes/keys.ts` | Write to a temp file, then rename. Set file mode `0600`. |

## 2. Correctness and reliability

- **No test suite** *(Phase 1: added; see below)*. Add Vitest. Highest value first: `detectIoc`, `normalizeIoc`, `extractIocs` (false positives such as version strings and file names), `defang`, and the backend scoring functions `computeOverallAssessment`, `detectContradictions` and `detectVpnOrTor`. These are pure functions and cheap to test.
- **`reloadConfig()` duplicates the startup config block** and has to be kept in sync by hand. Derive both from one `PROVIDER_ENV` table. The key allowlist in `keys.ts` is a third copy of the same list.
- **The cache rewrites the whole JSON file synchronously on every `set`** (`writeFileSync` with pretty-printing). Nothing calls `prune()`, so the file grows without bound. It also lives at the repo root `.cache/`, not `backend/.cache/` as the README says. Recommendation: debounce writes, prune on startup and on an interval, cap the entry count, or switch to SQLite (`better-sqlite3`).
- **The rate limiter only reacts to 429s.** It never enforces provider quotas proactively (VirusTotal free tier is 4 requests/min, and a batch triage run will burn through it). Add a token bucket per provider, configured from `providerTtl`-style data.
- **The "Email Header Review" workflow shows for every indicator type** because `isWorkflowEnabled` only checks that input is present. It should require `ioc.isEmailHeader`.
- **Hardcoded `BACKEND_URL = http://localhost:8787`, with CORS limited to ports 5173/5174.** `npm run preview` (port 4173) can't reach the backend. Use a Vite dev/preview proxy (`/api` → 8787) and relative URLs, and drop CORS entirely.
- **Timeouts stop before the response body is read.** *(Corrected in Phase 1: an earlier draft said some calls had no timeout; every call has one.)* Adapters clear their abort timer as soon as response headers arrive, so a slow response body can still hang a request. Each adapter also re-implements `makeResult`, `now` and its timeout handling. A shared helper using `AbortSignal.timeout()` that covers the body read would fix both.

- **Three different scoring implementations** *(unified after Phase 1)*. `/api/analyse`, `/api/enrich` (Batch triage) and `/api/analyse-email-header` each computed severity differently. `/api/enrich`, for example, counted passive sources such as WHOIS and IPinfo towards severity. All three now use `lib/scoring.ts`; the email route supplies its own action wording. Batch triage verdicts can therefore differ from before: passive-only hits no longer raise severity, Tor and VPN detection now applies, and confidence takes data freshness into account.

### Bugs found by the Phase 1 tests (all fixed)

| Area | Bug |
|---|---|
| Bulk extract | Defanged URLs in text were cut off at the first bracket (`hxxps://evil[.]com/x` was extracted as `https://evil`), and defanged domains (`evil[.]com`) were missed entirely |
| Bulk extract | Clock times in logs (`12:30:45`) were extracted as IPv6 addresses |
| Bulk extract | A CIDR's network address was also reported as a separate IPv4 address |
| Detection | Invalid CIDRs (`10.0.0.0/40`, `300.0.0.0/8`) were accepted; IPv6 validation accepted clock times |
| Detection | Ordinary URLs were flagged as sensitive by substring matching (`/android/video` matched "id"); terms are now matched as whole words in the path and parameter names, and JWT-looking parameter values are flagged |
| Detection | Mixed-case domains were classified at medium confidence |
| Email headers | DKIM alignment used a plain `endsWith`, so a signature from `notexample.com` passed for `From: example.com` |

## 3. Code health

- **Dead code:** `DetectionPanel`, `EnrichmentPanel`, `ProviderStatus`, `WarningBanner`, `lib/assessment.ts`, `lib/caseNote.ts`, `types/case.ts`. None of these are reachable from `App`. `DetectionPanel` still uses the old `slate-*` palette. Delete them, or restore the Cases and Assessment features the README promises.
- **Oversized components:** `AutoAnalysisPanel` (783 lines), `ToolsManagementPanel` (617), `enrichmentShared` (562) and `analyseEmailHeader.ts` (528) each mix parsing, data shaping and rendering. Split the parsers into `lib/` (narrative parsing, header parsing) so they can be tested.
- **`App.tsx` holds about 15 pieces of state and coordinates the analysis panel through `flushSync` plus an imperative ref.** Move investigation state into a reducer or context (`useInvestigation`). That removes the `flushSync`/`panelRef.run()` choreography.
- **Three separate localStorage history stores** (`soc-toolbox-ioc-history`, `searchHistory`, favourites). Consolidate them behind one versioned storage module.
- **`SOC-Analyst-Toolbox-Overview.html`** (52 KB) at the repo root duplicates the README. Move it to `docs/` or drop it.

## 4. Performance

- The frontend bundle is a single 460 KB JS chunk (126 KB gzipped). Lazy-load the non-default tabs (`React.lazy` for Threat feed, Tool library, About, Template check, Batch). The Investigate path should come in under about 250 KB.
- `tools.json` and `workflows.json` are bundled whole. That's fine at 60 tools; fetch them separately only if the library grows.
- `ToolCard` re-runs `buildTemplateVars` once per row. Compute it once in `ToolPanel` and pass it down.
- Backend `/api/analyse` fans out to up to 13 providers with `Promise.allSettled`, then blocks on Ollama for up to 90 s. Stream it: send provider results as they arrive (SSE), then the narrative. Perceived latency drops from about 60 s to about 2 s.

## 5. UX: changes made in this pass

**Root cause of the "AI-generated" look:** an Untitled-UI-style palette pasted as about 1,200 hex classes, pill-shaped badges everywhere, monogram "initials" tiles, emoji in controls, a shield-and-tick logo next to a pulsing "Local only" pill, a yellow banner on every page, the default Vite favicon, 10 flat tabs, and AI-flavoured copy ("AI-assisted verdict", ★ icon, "▶ Run").

**What changed:**

- **Design tokens.** `src/index.css` now defines a semantic palette (`canvas`, `surface`, `inset`, `raised`, `line*`, `fg-1…4`, `accent*`, and a severity scale `danger`/`high`/`warn`/`ok`/`violet`), with a full dark theme. All 1,201 hardcoded colour classes were codemodded to tokens, and the 50-rule dark-mode override hack is gone. Theme defaults to the OS preference.
- **Shape and type.** Tighter radii (4–8 px), shadows dropped, squared chips instead of pills, self-hosted IBM Plex Sans and Mono with slashed zero for indicators.
- **App shell** (`components/AppShell.tsx`). Grouped sidebar (Investigate / Intelligence / Utilities / Configuration), a page header with title and purpose, a real backend connection status in place of the decorative pill, the privacy note moved to the footer, and a responsive top nav on narrow screens. Tabs renamed: API Keys → Integrations, Manage Tools → Tool library, Config Check → Template check.
- **Investigate page.** Single command input with inline classification (key/value fields for URL parts). Keyboard shortcuts: `/` focuses the input, ⌘/Ctrl+↵ runs analysis, Esc clears. The workflow bar is a radio group with a clear primary action, the Run button is disabled with an explanation when the backend is offline, and "Bypass cache" replaces the ambiguous "Re-run".
- **Pivot tools** became a dense, scannable table (Tool / Exposure / Access / Open). Exposure labels now distinguish *Passive*, *Submits IOC* and *Public*; previously medium and high risk both read "Submits IOC". The Open button turns amber when the indicator is a sensitive URL and the tool shares it externally. The panel header counts how many tools leak the indicator.
- **Smaller fixes.** New logo mark and favicon (a defang-bracket motif), duplicated panel titles removed, unreadable inverted controls in dark mode fixed, raw "Failed to fetch" errors replaced with actionable text, unused Vite/React assets removed.

### UX: next steps

1. **Verdict-first results.** Merge `AutoAnalysisPanel` and `AnalysisResultsPanel` into one result view: a verdict header (severity, confidence, n/N providers), key facts, contradictions, then a provider table with expandable rows. There are currently two stacked cards with overlapping summaries.
2. **Case workspace.** Bring back Cases (the code exists in `lib/caseNote.ts` and `lib/assessment.ts`): verdict, analyst notes, checklist, markdown/JSON export, and history linked to cases.
3. **Command palette** (⌘K) for tab switching and recent indicators.
4. **Batch triage** as a sortable table with sticky severity column and CSV export.
5. **Empty states** with a sample indicator to try ("Try 185.220.101.4").
6. **Accessibility pass.** Focus order, `aria-live` for analysis progress, contrast check of `fg-4` text (currently decorative-only).

## 6. Prioritised plan

| Phase | Effort | Items |
|---|---|---|
| **0: Done** (2026-10-19) | ~1 day | S2 credential validator gated and uncached · S3 Host + Origin enforcement (launch token dropped: it can't stop local processes, which can read `.env` anyway) · S4 server-side tool validation + `safeHref` · S5 audits clean in both packages · README rewritten · dead code removed |
| **1: Done** (2026-10-19) | 3–5 days | 75 Vitest tests (49 frontend, 26 backend) covering detection, extraction, defang, templates, scoring, email header parsing and the provider registry · GitHub Actions CI · one provider registry drives config, reload and the key allowlist · `node-fetch` replaced with Node's built-in fetch · Vite dev/preview proxy with relative `/api` URLs · **Deferred:** shared HTTP helper (see "Timeouts" above) · scoring unification done as a follow-up commit |
| **2: Done** (2026-10-19) | 2–3 days | Secondary pages lazy-loaded (main bundle 460 → 357 KB, 126 → 103 KB gzipped; the planned ~250 KB wasn't realistic, since React 19 plus the tool and workflow catalogues needed on first paint are ~270 KB) · `/api/analyse/stream` (SSE) shows each provider and the verdict as they arrive, before the LLM summary; `/api/analyse` is unchanged · cache writes batched and atomic, with pruning, a 5,000-entry cap and a flush on shutdown · proactive per-provider rate limits (VirusTotal, ip-api, Shodan, HIBP), overridable with `RATE_LIMIT_<PROVIDER>` · **Regression found and fixed:** after the Phase 1 switch to built-in fetch, rdap.org rejected the default `User-Agent: node`, so IP WHOIS had been failing; all outbound requests now send `SOC-Analyst-Toolbox/1.0` |
| **3: Product UX** | 1–2 weeks | Verdict-first unified results view; Cases workspace; ⌘K palette; batch triage table; accessibility pass |
| **4: Hardening** | ongoing | Express 5; replace ip-api; split large components and move parsers into `lib/`; consolidated storage module with schema versioning |
