export type IocType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'email'
  | 'asn'
  | 'cidr'
  | 'cve';

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

export type EnrichmentStatus =
  | 'ok'
  | 'missing_key'
  | 'unsupported_ioc'
  | 'rate_limited'
  | 'error'
  | 'skipped_safety'
  | 'cached';

export type Severity = 'benign' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export type Confidence = 'low' | 'medium' | 'high' | 'unknown';

export interface IocInput {
  original: string;
  normalised: string;
  type: IocType;
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

export interface EnrichOptions {
  forceRefresh: boolean;
  allowSensitiveUrl: boolean;
  allowUrlSubmission: boolean;
  includeRaw: boolean;
  includeHunter: boolean;
}

export type AdapterFn = (ioc: IocInput, options: EnrichOptions) => Promise<EnrichmentResult>;
