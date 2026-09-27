// pwpolicy.test.js — the password policy the browser enforces (public/js/pwauth.js).
import { describe, it, expect } from 'vitest';
import { checkNewPassword, checkOwnerPassword, passwordLength, describePolicy, policyOf, DEFAULT_POLICY } from '../public/js/pwauth.js';

const strict = { pwMinLength: 14, pwUpper: true, pwLower: true, pwDigit: true, pwSymbol: true };

describe('password policy', () => {
  it('defaults to 12 characters and nothing else', () => {
    expect(checkNewPassword('a'.repeat(11))).toMatch(/at least 12/);
    expect(checkNewPassword('a'.repeat(12))).toBeNull();
    expect(describePolicy()).toBe('At least 12 characters.');
    expect(policyOf(undefined)).toEqual(DEFAULT_POLICY);
  });

  it('enforces every required class and names what is missing', () => {
    expect(checkNewPassword('abcdefghijklmn', undefined, strict)).toMatch(/upper-case letter, a digit, a symbol/);
    expect(checkNewPassword('Abcdefghijkl1!', undefined, strict)).toBeNull();
    expect(checkNewPassword('Abcdefgh1!', undefined, strict)).toMatch(/at least 14/);
    expect(describePolicy(strict)).toBe('At least 14 characters, including an upper-case letter, a lower-case letter, a digit and a symbol.');
  });

  it('counts characters, not UTF-16 units, and understands non-Latin scripts', () => {
    const p = { pwMinLength: 12, pwUpper: true, pwDigit: true };
    expect(checkNewPassword('Ωmega-😀😀😀😀😀5', undefined, p)).toBeNull();
    expect(checkNewPassword('😀'.repeat(6), undefined, { pwMinLength: 12 })).toMatch(/at least 12/); // 12 UTF-16 units, 6 characters
    expect(checkNewPassword('שלוםשלוםשלום1', undefined, { pwMinLength: 12, pwDigit: true })).toBeNull();
  });

  it('counts every character as typed: spaces, punctuation and combining marks too', () => {
    expect(passwordLength('a b c d e f ')).toBe(12);
    expect(passwordLength('   ')).toBe(3);
    expect(passwordLength('cafe\u0301')).toBe(5); // e + combining acute: two characters typed
    expect(checkNewPassword('cafe\u0301-cafe\u0301-', undefined, { pwMinLength: 12 })).toBeNull(); // 12 as typed (10 after NFC)
    expect(checkNewPassword(' '.repeat(12))).toBeNull();
  });

  it('passwords the owner sets follow no policy', () => {
    expect(checkOwnerPassword('x', 'x')).toBeNull();
    expect(checkOwnerPassword('', '')).toMatch(/Enter a password/);
    expect(checkOwnerPassword('abc', 'abd')).toMatch(/do not match/);
    expect(checkOwnerPassword('a'.repeat(1025))).toMatch(/at most/);
  });

  it('never goes below the built-in minimum, and checks the confirmation last', () => {
    expect(policyOf({ pwMinLength: 4 }).pwMinLength).toBe(12);
    expect(checkNewPassword('abcdefghijklm', 'different', DEFAULT_POLICY)).toMatch(/do not match/);
  });
});
