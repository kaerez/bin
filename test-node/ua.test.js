// ua.test.js — the read-receipt User-Agent / Accept-Language reader.
import { describe, it, expect } from 'vitest';
import { parseUserAgent, parseLanguages } from '../src/lib/ua.js';

describe('user agent', () => {
  it('names common browsers and systems', () => {
    expect(parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1')).toEqual({ browser: 'Safari', version: '26', os: 'iOS 26' });
    expect(parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.0.0 Mobile/15E148 Safari/604.1')).toMatchObject({ browser: 'Chrome', version: '140' });
    expect(parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0')).toEqual({ browser: 'Edge', version: '140', os: 'Windows 10/11' });
    expect(parseUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0')).toEqual({ browser: 'Firefox', version: '142', os: 'Linux' });
    expect(parseUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36')).toEqual({ browser: 'Chrome', version: '140', os: 'Android 14' });
    expect(parseUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/140.0.0.0 Safari/537.36')).toEqual({ browser: 'Chrome (headless)', version: '140', os: 'Linux' });
    expect(parseUserAgent('')).toEqual({ browser: '', version: '', os: '' });
    expect(parseUserAgent('something odd')).toEqual({ browser: 'other', version: '', os: 'other' });
  });
  it('keeps only well-formed language tags', () => {
    expect(parseLanguages('he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7,fr,de,x')).toBe('he-IL, he, en-US, en, fr');
    expect(parseLanguages('<script>,en')).toBe('en');
    expect(parseLanguages(null)).toBe('');
  });
});
