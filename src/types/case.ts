import type { AnalysisResponse } from './analysis';
import type { IocInput } from './enrichment';

export type CaseStatus = 'open' | 'closed';

export type CaseVerdict =
  | 'benign'
  | 'noise'
  | 'suspicious'
  | 'likely_malicious'
  | 'malicious'
  | 'inconclusive';

export type CaseConfidence = 'low' | 'medium' | 'high';

export interface CaseRecord {
  id: string;
  title: string;
  ticketRef: string;
  status: CaseStatus;
  createdAt: string;
  updatedAt: string;
  ioc: IocInput;
  workflowId: string | null;
  verdict: CaseVerdict | '';
  confidence: CaseConfidence | '';
  actionsTaken: string[];
  /** Checklist item text → done */
  checklist: Record<string, boolean>;
  notes: string;
  /** Snapshot of the analysis the analyst based the verdict on */
  analysis: AnalysisResponse | null;
}

/** Fields the analyst edits; the rest is managed by the case store. */
export type CaseDraft = Pick<
  CaseRecord,
  'title' | 'ticketRef' | 'verdict' | 'confidence' | 'actionsTaken' | 'checklist' | 'notes'
>;
