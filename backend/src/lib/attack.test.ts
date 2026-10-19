import { describe, it, expect } from 'vitest';
import { collectAttackRefs } from './attack.js';

describe('collectAttackRefs', () => {
  it('keeps valid technique ids, cleans names and de-duplicates', () => {
    expect(collectAttackRefs([
      { id: 'T1071', name: 'T1071 - Application Layer Protocol' },
      { id: 't1071.001', name: 'Web Protocols' },
      { id: 'T1071' },
      { id: 'TA0011', name: 'Command and Control' },
      { id: 'not-an-id' },
      { id: 42 },
    ])).toEqual([
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1071.001', name: 'Web Protocols' },
    ]);
  });
});
