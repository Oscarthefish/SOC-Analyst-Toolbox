export type EnrichmentStatus =
  | 'ok'
  | 'missing_key'
  | 'unsupported_ioc'
  | 'rate_limited'
  | 'error'
  | 'skipped_safety'
  | 'cached';

export type FreshnessLabel = 'last24h' | 'last7d' | 'last30d' | 'historical' | 'unknown';

export type SourceTier = 'authoritative' | 'commercial-ti' | 'community' | 'reputation' | 'passive-infra';

export interface KeyFact {
  label: string;
  value: string;
  timestamp?: string;
}

export interface ContradictionFlag {
  type: string;
  message: string;
  sources: string[];
  recommendation: string;
}

export type Severity = 'benign' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export type Confidence = 'low' | 'medium' | 'high' | 'unknown';

export interface IocInput {
  original: string;
  normalised: string;
  type: string;
}

export interface EnrichmentResult {
  providerId: string;
  providerName: string;
  status: EnrichmentStatus;
  summary: string;
  severity: Severity;
  confidence: Confidence;
  data: Record<string, unknown>;
  rawAvailable: boolean;
  checkedAt: string;
  fromCache: boolean;
  sourceUrl?: string;
  errorMessage?: string;
  lastSeenDate?: string;
  firstSeenDate?: string;
  sourceDataTimestamp?: string;
  freshnessLabel?: FreshnessLabel;
  sourceReliability?: SourceTier;
  keyFacts?: KeyFact[];
  contradicts?: string[];
  resolvedIps?: string[];
  relatedDomains?: string[];
  /** MITRE ATT&CK techniques the provider itself associates with the indicator */
  attackTechniques?: AttackRef[];
}

export interface AttackRef {
  /** Technique id, e.g. T1071 or T1071.001 */
  id: string;
  /** Name as given by the provider, when it supplies one */
  name?: string;
}

export interface OverallAssessment {
  severity: Severity;
  confidence: Confidence;
  summary: string;
  recommendedActions: string[];
}

export interface EnrichmentResponse {
  ioc: IocInput;
  results: EnrichmentResult[];
  overall: OverallAssessment;
  contradictions?: ContradictionFlag[];
}

export interface EnrichRequest {
  ioc: IocInput;
  workflowId?: string;
  providers?: string[];
  options?: {
    includeRaw?: boolean;
    forceRefresh?: boolean;
    allowSensitiveUrl?: boolean;
    allowUrlSubmission?: boolean;
  };
}

export interface HealthResponse {
  ok: boolean;
  service: string;
  configuredProviders: string[];
  flags: {
    enableUrlSubmission: boolean;
    enableHighRiskEnrichment: boolean;
  };
}
