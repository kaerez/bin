// url.test.js — share-URL parsing/building and server normalization. All
// parsing must fail closed BEFORE any network activity (a bad fragment or a
// non-HTTPS server is rejected at parse time), and there is no default server.
import { describe, it, expect } from 'vitest';
import { b64urlFromBytes } from '../vendor/bytes.js';
import { UsageError } from '../src/errors.js';
import {
  buildShareUrl, isIdOfClass, kindOf, normalizeServer, parseShareUrl, parseUrlOrId, requireServer,
} from '../src/url.js';

const FRAG = b64urlFromBytes(new Uint8Array(32).fill(7)); // 32 bytes → valid F
const KID = 'k' + b64urlFromBytes(new Uint8Array(16).fill(1)); // 22-char b64url
const BID = 'b' + b64urlFromBytes(new Uint8Array(16).fill(2));
const FID = 'f' + b64urlFromBytes(new Uint8Array(16).fill(3));

describe('parseShareUrl', () => {
  it('parses valid https share URLs for every id class', () => {
    for (const id of [KID, BID, FID]) {
      expect(parseShareUrl(`https://secbin.example.com/p/${id}#${FRAG}`))
        .toEqual({ server: 'https://secbin.example.com', id, fragment: FRAG });
    }
  });

  it('allows http for localhost (wrangler dev) only', () => {
    expect(parseShareUrl(`http://localhost:8787/p/${KID}#${FRAG}`).server).toBe('http://localhost:8787');
    expect(parseShareUrl(`http://127.0.0.1:8787/p/${BID}#${FRAG}`).id).toBe(BID);
    expect(() => parseShareUrl(`http://secbin.example.com/p/${KID}#${FRAG}`)).toThrow(UsageError);
  });

  it('rejects a missing or short fragment before any network use', () => {
    expect(() => parseShareUrl(`https://x.example/p/${KID}`)).toThrow(/fragment/);
    expect(() => parseShareUrl(`https://x.example/p/${KID}#`)).toThrow(/fragment/);
    const short = b64urlFromBytes(new Uint8Array(16)); // 16 bytes ≠ 32
    expect(() => parseShareUrl(`https://x.example/p/${KID}#${short}`)).toThrow(/invalid key/);
    expect(() => parseShareUrl(`https://x.example/p/${KID}#not!base64url`)).toThrow(/invalid key/);
  });

  it('rejects malformed ids, unknown classes and non-share paths', () => {
    expect(() => parseShareUrl(`https://x.example/p/xyz#${FRAG}`)).toThrow(/malformed share id/);
    expect(() => parseShareUrl(`https://x.example/p/z${KID.slice(1)}#${FRAG}`)).toThrow(/malformed share id/);
    expect(() => parseShareUrl(`https://x.example/q/${KID}#${FRAG}`)).toThrow(/share URL/);
    expect(() => parseShareUrl('not a url')).toThrow(UsageError);
  });

  it('rejects URLs with embedded credentials', () => {
    expect(() => parseShareUrl(`https://user:pw@x.example/p/${KID}#${FRAG}`)).toThrow(/credentials/);
  });
});

describe('buildShareUrl / kindOf / isIdOfClass', () => {
  it('round-trips through parseShareUrl', () => {
    const url = buildShareUrl('https://x.example', BID, FRAG);
    expect(url).toBe(`https://x.example/p/${BID}#${FRAG}`);
    expect(parseShareUrl(url)).toEqual({ server: 'https://x.example', id: BID, fragment: FRAG });
  });

  it('maps file ids to /api/file and notes to /api/paste', () => {
    expect(kindOf(FID)).toBe('file');
    expect(kindOf(BID)).toBe('paste');
    expect(kindOf(KID)).toBe('paste');
  });

  it('checks a server-returned id against the expected storage class', () => {
    expect(isIdOfClass(BID, 'b')).toBe(true);
    expect(isIdOfClass(KID, 'b')).toBe(false);
    expect(isIdOfClass('b/../x', 'b')).toBe(false);
    expect(isIdOfClass(undefined, 'f')).toBe(false);
  });
});

describe('normalizeServer / requireServer', () => {
  it('normalizes to a bare origin', () => {
    expect(normalizeServer('https://secbin.example.com')).toBe('https://secbin.example.com');
    expect(normalizeServer('https://secbin.example.com/')).toBe('https://secbin.example.com');
    expect(normalizeServer('http://localhost:8787')).toBe('http://localhost:8787');
  });

  it('rejects http (non-local), paths, queries, and junk', () => {
    expect(() => normalizeServer('http://secbin.example.com')).toThrow(/non-HTTPS/);
    expect(() => normalizeServer('https://x.example/api')).toThrow(/bare origin/);
    expect(() => normalizeServer('https://x.example/?a=1')).toThrow(/bare origin/);
    expect(() => normalizeServer('nonsense')).toThrow(UsageError);
  });

  it('has no default: --server, then SECBIN_SERVER, else a usage error', () => {
    expect(requireServer('https://a.example', { SECBIN_SERVER: 'https://b.example' })).toBe('https://a.example');
    expect(requireServer(undefined, { SECBIN_SERVER: 'https://b.example' })).toBe('https://b.example');
    expect(() => requireServer(undefined, {})).toThrow(/SECBIN_SERVER/);
    expect(() => requireServer(undefined, { SECBIN_SERVER: '' })).toThrow(UsageError);
  });
});

describe('parseUrlOrId', () => {
  it('accepts a bare id with a fallback server', () => {
    expect(parseUrlOrId(FID, 'https://fallback.example')).toEqual({ server: 'https://fallback.example', id: FID });
  });

  it('a bare id without any server is a usage error', () => {
    expect(() => parseUrlOrId(KID, undefined)).toThrow(/--server|SECBIN_SERVER/);
  });

  it('accepts a share URL with or without its fragment (its origin wins)', () => {
    expect(parseUrlOrId(`https://x.example/p/${BID}#${FRAG}`, 'https://fallback.example')).toEqual({ server: 'https://x.example', id: BID });
    expect(parseUrlOrId(`https://x.example/p/${BID}`, undefined)).toEqual({ server: 'https://x.example', id: BID });
  });

  it('rejects malformed ids', () => {
    expect(() => parseUrlOrId('nope', 'https://fallback.example')).toThrow(/malformed share id/);
  });
});
