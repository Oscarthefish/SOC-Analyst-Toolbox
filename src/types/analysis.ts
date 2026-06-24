import type { EnrichmentResult, OverallAssessment, IocInput, ContradictionFlag } from './enrichment';

export interface AnalysisRequest {
  ioc: IocInput;
  workflowId?: string;
  options?: {
    ollamaModel?: string;
    forceRefresh?: boolean;
    includeHunter?: boolean;
  };
}

export interface AnalysisResponse {
  ioc: IocInput;
  results: EnrichmentResult[];
  overall: OverallAssessment;
  narrative: string | null;
  narrativeError?: string;
  ollamaModel: string;
  ollamaAvailable: boolean;
  analysedAt: string;
  contradictions?: ContradictionFlag[];
}

export interface ParsedEmailHeaders {
  sendingIp: string | null;
  fromAddress: string | null;
  fromDomain: string | null;
  toAddress: string | null;
  toAddresses: string[];
  returnPathDomain: string | null;
  envelopeDomain: string | null;
  replyToDomain: string | null;
  replyToAddress: string | null;
  deliveredTo: string | null;
  dkimDomain: string | null;
  subject: string | null;
  messageId: string | null;
  date: string | null;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  dmarcPolicy: string | null;
  spamScore: string | null;
  receivedSpf: string | null;
  authResults: string | null;
  hops: string[];
  suspiciousIndicators: string[];
}

export interface EmailHeaderAnalysisResponse {
  parsed: ParsedEmailHeaders;
  ipIoc: IocInput | null;
  domIoc: IocInput | null;
  results: EnrichmentResult[];
  ipResults: EnrichmentResult[];
  domResults: EnrichmentResult[];
  overall: OverallAssessment;
  narrative: string | null;
  narrativeError?: string;
  ollamaModel: string;
  ollamaAvailable: boolean;
  analysedAt: string;
}

export interface EmailHeaderAnalysisRequest {
  rawHeaders: string;
  options?: {
    ollamaModel?: string;
    forceRefresh?: boolean;
  };
}
