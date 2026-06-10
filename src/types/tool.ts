import type { IocType } from './ioc';

export type SubmissionRisk = 'low' | 'medium' | 'high';
export type RequiresAccount = 'none' | 'free_account' | 'trial' | 'paid' | 'mixed';

export interface Tool {
  id: string;
  name: string;
  category: string;
  description: string;
  inputTypes: IocType[];
  workflows: string[];
  urlTemplate: string;
  whyUse: string;
  lookFor: string;
  riskNote: string;
  submissionRisk: SubmissionRisk;
  requiresAccount: RequiresAccount;
  tags: string[];
}
