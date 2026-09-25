// sharetypes.test.js — URL and secret share payloads (browser + CLI), and the
// TOTP generator against the RFC 6238 Appendix B test vectors.
import { describe, it, expect } from 'vitest';
import { parseShareUrl, describeHost, buildSecret, parseSecret, parseTotp, totpCode, base32Decode, ShareTypeError, normalizeUrlRules, urlAllowed, urlRulesOf, describeUrlRules } from '../public/js/sharetypes.js';

const b32 = (ascii) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = ''; for (const c of ascii) bits += c.charCodeAt(0).toString(2).padStart(8, '0');
  let out = ''; for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
};

describe('url shares', () => {
  it('accept only absolute http(s) links without credentials or control characters', () => {
    expect(parseShareUrl(' https://example.com/a?b=1#c ').href).toBe('https://example.com/a?b=1#c');
    for (const bad of ['', 'example.com', 'javascript:alert(1)', 'data:text/html,x', 'ftp://x', 'https://user:pw@x.com', 'https://x.com/\u0000', 'https://x.com/a b', 'https://' + 'a'.repeat(2050)]) {
      expect(() => parseShareUrl(bad)).toThrow(ShareTypeError);
    }
  });
  it('spell out the real host, flagging IDN look-alikes and plain http', () => {
    expect(describeHost(parseShareUrl('https://xn--mnchen-3ya.de/'))).toEqual({ ascii: 'xn--mnchen-3ya.de', unicode: 'münchen.de', idn: true, insecure: false, scheme: 'https', external: false });
    expect(describeHost(parseShareUrl('https://münchen.de/')).ascii).toBe('xn--mnchen-3ya.de');
    expect(describeHost(parseShareUrl('http://example.com/'))).toMatchObject({ idn: false, insecure: true });
  });
});

describe('secret shares', () => {
  it('round-trip, drop empty fields and refuse junk', () => {
    const text = buildSecret({ title: 'VPN', username: 'alice', password: 'hunter2', url: 'https://vpn.example.com', notes: '', totp: '' });
    expect(JSON.parse(text)).toEqual({ v: 1, title: 'VPN', username: 'alice', password: 'hunter2', url: 'https://vpn.example.com' });
    expect(parseSecret(text)).toEqual({ title: 'VPN', username: 'alice', password: 'hunter2', url: 'https://vpn.example.com' });
    expect(() => buildSecret({})).toThrow(/at least one/);
    expect(() => buildSecret({ url: 'javascript:alert(1)' })).toThrow(ShareTypeError);
    expect(() => buildSecret({ password: 'x'.repeat(4097) })).toThrow(/too long/);
    for (const bad of ['nope', '[]', '{"v":2}', '{"v":1,"evil":"x"}', '{"v":1,"password":1}', '{"v":1,"__proto__":"x"}']) {
      expect(() => parseSecret(bad)).toThrow(ShareTypeError);
    }
  });
});

describe('TOTP (RFC 6238 Appendix B)', () => {
  const seeds = {
    'SHA-1': b32('12345678901234567890'),
    'SHA-256': b32('12345678901234567890123456789012'),
    'SHA-512': b32('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1234567890, '89005924', '91819424', '93441116'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  it('matches every vector for SHA-1, SHA-256 and SHA-512', async () => {
    for (const [t, s1, s256, s512] of vectors) {
      for (const [alg, want] of [['SHA1', s1], ['SHA256', s256], ['SHA512', s512]]) {
        const seed = seeds[{ SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[alg]];
        const { code } = await totpCode(`otpauth://totp/x?secret=${seed}&algorithm=${alg}&digits=8`, t * 1000);
        expect([t, alg, code]).toEqual([t, alg, want]);
      }
    }
  });
  it('defaults to 6 digits / 30 s / SHA-1 for a bare seed and reports the time left', async () => {
    const r = await totpCode(seeds['SHA-1'], 59 * 1000);
    expect(r).toEqual({ code: '287082', remaining: 1, period: 30 });
  });
  it('rejects bad seeds and parameters', () => {
    for (const bad of ['not base32!', 'AAAA', 'otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ', 'otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBV&digits=9', 'otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBV&algorithm=MD5']) {
      expect(() => parseTotp(bad)).toThrow(ShareTypeError);
    }
    expect(Array.from(base32Decode('mzxw6==='))).toEqual([102, 111, 111]);
  });
});

describe('review hardening', () => {
  it('bounds the normalized href, not just the typed text', () => {
    const typed = `https://example.com/${'é'.repeat(1000)}`;
    expect(typed.length).toBeLessThan(2048);
    expect(() => parseShareUrl(typed)).toThrow(/too long once encoded/);
  });

  it('an empty credential is not a credential', () => {
    expect(() => parseSecret('{"v":1}')).toThrow(ShareTypeError);
  });

  it('otpauth algorithm names are looked up safely', () => {
    for (const alg of ['__proto__', 'constructor', 'toString']) {
      expect(() => parseTotp(`otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=${alg}`)).toThrow(/Unsupported/);
    }
  });
});

describe('URL rules (the admin\'s "links that may be shared")', () => {
  it('defaults to http and https, and never allows dangerous schemes', () => {
    expect(() => parseShareUrl('tel:+15551234')).toThrow(/not allowed for your account/);
    for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'vbscript:x', 'blob:https://a/b']) {
      expect(() => parseShareUrl(bad, { rules: ['scheme:*'] })).toThrow(ShareTypeError);
      expect(() => parseShareUrl(bad, { recipient: true })).toThrow(ShareTypeError);
    }
  });

  it('allows extra schemes and anchored regular expressions', () => {
    expect(parseShareUrl('tel:+15551234', { rules: ['scheme:tel'] }).href).toBe('tel:+15551234');
    const rules = ['re:^https://([a-z0-9-]+\\.)*example\\.com/'];
    expect(parseShareUrl('https://docs.EXAMPLE.com/x', { rules }).href).toBe('https://docs.example.com/x');
    expect(() => parseShareUrl('https://evil.test/?example.com/', { rules })).toThrow(/not allowed/);
    expect(urlAllowed(new URL('mailto:a@b.test'), ['scheme:*'])).toBe(true);
  });

  it('validates rule lists (scheme names, forbidden schemes, regex syntax, size)', () => {
    expect(normalizeUrlRules([' scheme:HTTPS: ', 'scheme:tel', 'scheme:tel', ''])).toEqual(['scheme:https', 'scheme:tel']);
    expect(() => normalizeUrlRules(['scheme:data'])).toThrow(/never be allowed/);
    expect(() => normalizeUrlRules(['https'])).toThrow(/start a rule with/);
    expect(() => normalizeUrlRules(['re:(['])).toThrow();
    expect(() => normalizeUrlRules(Array.from({ length: 51 }, (_, i) => `scheme:s${i}`))).toThrow(/at most 50/);
    expect(urlRulesOf(['scheme:data'])).toEqual(['scheme:http', 'scheme:https']); // untrusted input falls back
    expect(describeUrlRules(['scheme:http', 'scheme:https', 'scheme:tel'])).toBe('http, https and tel links');
  });

  it('recipients accept any safe scheme and see host-less links for what they are', () => {
    const u = parseShareUrl('sms:+15551234', { recipient: true });
    expect(describeHost(u)).toMatchObject({ external: true, scheme: 'sms', ascii: 'sms:+15551234' });
    expect(describeHost(new URL('https://example.com/'))).toMatchObject({ external: false, scheme: 'https' });
  });
});
