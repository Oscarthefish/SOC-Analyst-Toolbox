import type { IocType } from './ioc';

export interface InternalSearch {
  label: string;
  template: string;
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  allowedInputTypes: IocType[];
  toolIds: string[];
  checklist: string[];
  internalSearches: InternalSearch[];
  expectedOutcome: string;
}
