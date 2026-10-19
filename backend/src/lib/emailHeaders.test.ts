import { describe, it, expect } from 'vitest';
import { parseEmailHeaders } from './emailHeaders.js';

const PHISH = [
  'Received: from mail.relay.example (mail.relay.example [10.1.2.3])',
  '\tby mx.victim.com with ESMTPS id abc; Mon, 1 Jan 2024 10:00:00 +0000',
  'Received: from attacker-box (unknown [203.0.113.45])',
  '\tby mail.relay.example with SMTP id def',
  'Authentication-Results: mx.victim.com; spf=softfail smtp.mailfrom=bulk-mailer.net;',
  '\tdkim=fail header.d=bulk-mailer.net; dmarc=fail (p=REJECT) header.from=paypa1.com',
  'Return-Path: <bounce@bulk-mailer.net>',
  'From: "PayPal Support" <support@paypa1.com>',
  'Reply-To: collect@gmail.com',
  'To: alice@victim.com',
  'Subject: Your account is limited',
  'DKIM-Signature: v=1; a=rsa-sha256; d=bulk-mailer.net; s=k1; b=xyz',
  'X-Spam-Score: 12.5',
  'Message-ID: <123@paypa1.com>',
].join('\r\n');

describe('parseEmailHeaders', () => {
  const p = parseEmailHeaders(PHISH);

  it('extracts addresses and domains', () => {
    expect(p).toMatchObject({
      fromDomain: 'paypa1.com',
      returnPathDomain: 'bulk-mailer.net',
      replyToDomain: 'gmail.com',
      dkimDomain: 'bulk-mailer.net',
      subject: 'Your account is limited',
    });
  });

  it('picks the first public IP in the Received chain as the sender', () => {
    expect(p.sendingIp).toBe('203.0.113.45');
  });

  it('unfolds multi-line headers and parses auth results', () => {
    expect(p).toMatchObject({ spf: 'softfail', dkim: 'fail', dmarc: 'fail' });
  });

  it('raises the expected suspicious indicators', () => {
    const joined = p.suspiciousIndicators.join('\n');
    expect(joined).toMatch(/differs from Return-Path/);
    expect(joined).toMatch(/Reply-To domain \(gmail\.com\)/);
    expect(joined).toMatch(/DKIM signing domain/);
    expect(joined).toMatch(/SPF SOFTFAIL/);
    expect(joined).toMatch(/DMARC FAIL/);
    expect(joined).toMatch(/High spam score/);
  });

  it('accepts a DKIM signature from a parent domain of From', () => {
    const p2 = parseEmailHeaders('From: a@mail.example.com\nDKIM-Signature: d=example.com; s=x');
    expect(p2.suspiciousIndicators.join()).not.toMatch(/DKIM signing domain/);
  });

  it('flags a DKIM domain that merely shares a suffix with From', () => {
    // "evilexample.com" is not a subdomain of "example.com"
    const p2 = parseEmailHeaders('From: a@evilexample.com\nDKIM-Signature: d=example.com; s=x');
    expect(p2.suspiciousIndicators.join()).toMatch(/DKIM signing domain \(example\.com\) does not match/);
    // Attacker signs with a look-alike while spoofing the real From domain
    const p3 = parseEmailHeaders('From: ceo@example.com\nDKIM-Signature: d=notexample.com; s=x');
    expect(p3.suspiciousIndicators.join()).toMatch(/DKIM signing domain \(notexample\.com\) does not match/);
  });

  it('flags self-sent messages', () => {
    const p2 = parseEmailHeaders('From: Bob <bob@corp.com>\nTo: bob@corp.com');
    expect(p2.suspiciousIndicators.join()).toMatch(/Self-sent/);
  });
});
