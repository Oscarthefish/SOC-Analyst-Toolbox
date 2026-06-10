export type CaseVerdict =
  | 'benign'
  | 'known_scanner_noise'
  | 'suspicious'
  | 'likely_malicious'
  | 'confirmed_malicious'
  | 'inconclusive';

export type CaseConfidence = 'low' | 'medium' | 'high';

export interface AssessmentState {
  verdict: CaseVerdict | '';
  confidence: CaseConfidence | '';
  actionsTaken: string[];
}

export interface SavedCase {
  id: string;
  title: string;
  ticketReference: string;
  createdAt: string;
  updatedAt: string;
  iocs: string[];
  selectedWorkflowIds: string[];
  notes: string;
  verdict: CaseVerdict | '';
  confidence: CaseConfidence | '';
  actionsTaken: string[];
  checklistState: Record<string, boolean>;
}
