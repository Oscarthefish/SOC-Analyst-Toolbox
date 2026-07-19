/**
 * Read-only credential validator.
 *
 * Validates a credential against the issuing service's own API using only
 * read-only, non-destructive calls. No credential value is stored, logged,
 * or forwarded to any third party.
 *
 * This adapter is NOT included in any default workflow. It must be requested
 * explicitly by name (providers: ['credvalidate']) and only used during
 * authorized incident-response or red-team assessments.
 */
import fetch from 'node-fetch';
import type { IocInput, EnrichmentResult, EnrichOptions } from '../types.js';

const PROVIDER_ID = 'credvalidate';
const PROVIDER_NAME = 'Credential Validator';
const TIMEOUT_MS = 10_000;

function now(): string {
  return new Date().toISOString();
}

function makeResult(overrides: Partial<EnrichmentResult>): EnrichmentResult {
  return {
    providerId: PROVIDER_ID,
    providerName: PROVIDER_NAME,
    status: 'ok',
    summary: '',
    severity: 'unknown',
    confidence: 'unknown',
    data: {},
    rawAvailable: false,
    checkedAt: now(),
    fromCache: false,
    ...overrides,
  };
}

// Pattern detection — classify the credential type from the raw value
function detectCredentialType(value: string): string | null {
  if (/^AKIA[0-9A-Z]{16}$/.test(value))                              return 'aws-access-key';
  if (/^sk-ant-(?:api03|admin01)-/.test(value))                       return 'anthropic';
  if (/^sk-proj-/.test(value) || /^sk-[A-Za-z0-9]{20}T3BlbkFJ/.test(value)) return 'openai';
  if (/^ghp_[A-Za-z0-9]{36}$/.test(value))                           return 'github-pat';
  if (/^github_pat_[A-Za-z0-9_]{82}$/.test(value))                   return 'github-pat-fine';
  if (/^xoxb-\d+-\d+-[A-Za-z0-9]+$/.test(value))                     return 'slack-bot';
  if (/^xoxp-\d+-\d+-\d+-[a-f0-9]+$/.test(value))                    return 'slack-user';
  if (/^npm_[A-Za-z0-9]{36}$/.test(value))                           return 'npm-token';
  if (/^hf_[A-Za-z0-9]{37}$/.test(value))                            return 'huggingface';
  if (/^glpat-[A-Za-z0-9\-_]{20}$/.test(value))                      return 'gitlab-pat';
  if (/^sk_live_[A-Za-z0-9]{24,}$/.test(value))                      return 'stripe-secret';
  if (/^PMAK-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-/.test(value)) return 'postman-pmak';
  return null;
}

interface ValidationOutcome {
  valid: boolean;
  detail: string;
  scope?: string;
  identity?: string;
}

async function validateAwsKey(accessKey: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const body = 'Action=GetCallerIdentity&Version=2011-06-15';
  // AWS STS doesn't need a secret key to return a signed-request failure — it will
  // return InvalidClientTokenId for unknown keys vs SignatureDoesNotMatch for known keys.
  const res = await fetch('https://sts.amazonaws.com/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal,
  });
  const text = await res.text();
  if (text.includes('InvalidClientTokenId')) {
    return { valid: false, detail: 'AWS key ID is not recognized (InvalidClientTokenId).' };
  }
  if (text.includes('SignatureDoesNotMatch') || text.includes('AuthFailure')) {
    return { valid: true, detail: 'AWS key ID exists (signature mismatch expected — no secret provided).' };
  }
  return { valid: false, detail: `AWS STS returned unexpected response (HTTP ${res.status}).` };
}

async function validateGitHub(token: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const res = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'SOC-Analyst-Toolbox/1.0' },
    signal,
  });
  if (res.status === 200) {
    const data = (await res.json()) as { login?: string; scopes?: string };
    const scopes = res.headers.get('x-oauth-scopes') ?? '';
    return { valid: true, detail: 'Token is valid.', identity: data.login, scope: scopes || 'unknown' };
  }
  if (res.status === 401) return { valid: false, detail: 'Token is invalid or revoked (401).' };
  return { valid: false, detail: `GitHub returned HTTP ${res.status}.` };
}

async function validateSlack(token: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const res = await fetch('https://slack.com/api/auth.test', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    signal,
  });
  const data = (await res.json()) as { ok?: boolean; user?: string; team?: string; error?: string };
  if (data.ok) {
    return { valid: true, detail: 'Token is valid.', identity: data.user, scope: data.team };
  }
  return { valid: false, detail: `Slack auth.test returned ok=false: ${data.error ?? 'unknown error'}.` };
}

async function validateAnthropic(key: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const res = await fetch('https://api.anthropic.com/v1/models', {
    headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    signal,
  });
  if (res.status === 200) return { valid: true, detail: 'Key is valid (models endpoint returned 200).' };
  if (res.status === 401) return { valid: false, detail: 'Key is invalid or revoked (401).' };
  return { valid: false, detail: `Anthropic returned HTTP ${res.status}.` };
}

async function validateOpenAI(key: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const res = await fetch('https://api.openai.com/v1/models', {
    headers: { Authorization: `Bearer ${key}` },
    signal,
  });
  if (res.status === 200) return { valid: true, detail: 'Key is valid (models endpoint returned 200).' };
  if (res.status === 401) return { valid: false, detail: 'Key is invalid or revoked (401).' };
  return { valid: false, detail: `OpenAI returned HTTP ${res.status}.` };
}

async function validateNpm(token: string, signal: AbortSignal): Promise<ValidationOutcome> {
  const res = await fetch('https://registry.npmjs.org/-/whoami', {
    headers: { Authorization: `Bearer ${token}` },
    signal,
  });
  if (res.status === 200) {
    const data = (await res.json()) as { username?: string };
    return { valid: true, detail: 'Token is valid.', identity: data.username };
  }
  return { valid: false, detail: `npm returned HTTP ${res.status}.` };
}

export async function credvalidate(
  ioc: IocInput,
  _options: EnrichOptions,
): Promise<EnrichmentResult> {
  if (ioc.type !== 'secret') {
    return makeResult({
      status: 'unsupported_ioc',
      summary: `Credential Validator only supports IOC type 'secret'. Got: ${ioc.type}.`,
    });
  }

  const value = ioc.normalised;
  const credType = detectCredentialType(value);

  if (!credType) {
    return makeResult({
      status: 'unsupported_ioc',
      summary: 'Could not identify credential type from the supplied value.',
    });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let outcome: ValidationOutcome;

    switch (credType) {
      case 'aws-access-key':
        outcome = await validateAwsKey(value, controller.signal);
        break;
      case 'github-pat':
      case 'github-pat-fine':
        outcome = await validateGitHub(value, controller.signal);
        break;
      case 'slack-bot':
      case 'slack-user':
        outcome = await validateSlack(value, controller.signal);
        break;
      case 'anthropic':
        outcome = await validateAnthropic(value, controller.signal);
        break;
      case 'openai':
        outcome = await validateOpenAI(value, controller.signal);
        break;
      case 'npm-token':
        outcome = await validateNpm(value, controller.signal);
        break;
      default:
        return makeResult({
          status: 'unsupported_ioc',
          summary: `Validation not implemented for credential type: ${credType}.`,
        });
    }

    clearTimeout(timeout);

    const severity = outcome.valid ? 'critical' : 'benign';
    const statusLabel = outcome.valid ? 'VALID (active)' : 'INVALID (revoked/unknown)';

    return makeResult({
      status: 'ok',
      summary: `Credential Validator: ${credType} — ${statusLabel}. ${outcome.detail}`,
      severity,
      confidence: 'high',
      data: {
        credentialType: credType,
        isValid: outcome.valid,
        identity: outcome.identity,
        scope: outcome.scope,
      },
      sourceReliability: 'authoritative',
      keyFacts: [
        { label: 'Credential type', value: credType },
        { label: 'Status', value: statusLabel },
        ...(outcome.identity ? [{ label: 'Identity', value: outcome.identity }] : []),
        ...(outcome.scope ? [{ label: 'Scope / Workspace', value: outcome.scope }] : []),
        { label: 'Validation detail', value: outcome.detail },
      ],
    });
  } catch (err) {
    clearTimeout(timeout);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return makeResult({
      status: 'error',
      summary: isTimeout ? 'Credential validation timed out.' : 'Credential validation failed.',
      errorMessage: err instanceof Error ? err.message : String(err),
    });
  }
}
