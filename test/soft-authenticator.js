// soft-authenticator.js — a software WebAuthn authenticator for the workerd
// suites: real key pairs (ES256, EdDSA, RS256), real CBOR, real signatures,
// so src/lib/webauthn.js is exercised exactly as a browser would drive it.
// Knobs let a test break one property at a time (origin, UV, counter, …).
import { b64urlFromBytes, bytesFromB64url, utf8, randomBytes } from '../public/js/bytes.js';

// ── a minimal CBOR encoder (what WebAuthn needs) ────────────────────────────
function head(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 256) return [(major << 5) | 24, n];
  if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
  return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function cbor(v) {
  const out = [];
  const enc = (x) => {
    if (typeof x === 'number') { if (x >= 0) out.push(...head(0, x)); else out.push(...head(1, -1 - x)); return; }
    if (typeof x === 'string') { const b = utf8(x); out.push(...head(3, b.length), ...b); return; }
    if (x instanceof Uint8Array) { out.push(...head(2, x.length), ...x); return; }
    if (x instanceof Map) { out.push(...head(5, x.size)); for (const [k, val] of x) { enc(k); enc(val); } return; }
    if (Array.isArray(x)) { out.push(...head(4, x.length)); x.forEach(enc); return; }
    if (typeof x === 'boolean') { out.push(x ? 0xf5 : 0xf4); return; }
    throw new Error('cbor: unsupported');
  };
  enc(v);
  return new Uint8Array(out);
}

const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

const ALGS = {
  [-7]: { gen: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' } },
  [-8]: { gen: { name: 'Ed25519' }, sign: { name: 'Ed25519' } },
  [-257]: { gen: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
};

export class SoftAuthenticator {
  /** One passkey per instance. `counter`: use a signature counter (else always 0). */
  constructor({ alg = -7, counter = false } = {}) {
    this.alg = alg;
    this.counter = counter;
    this.count = 0;
    this.credId = randomBytes(32);
    this.id = b64urlFromBytes(this.credId);
  }

  async #coseKey() {
    const jwk = await crypto.subtle.exportKey('jwk', this.keys.publicKey);
    const b = (s) => bytesFromB64url(s);
    if (this.alg === -7) return new Map([[1, 2], [3, -7], [-1, 1], [-2, b(jwk.x)], [-3, b(jwk.y)]]);
    if (this.alg === -8) return new Map([[1, 1], [3, -8], [-1, 6], [-2, b(jwk.x)]]);
    return new Map([[1, 3], [3, -257], [-1, b(jwk.n)], [-2, b(jwk.e)]]);
  }

  #flags({ up = true, uv = true, at = false } = {}) {
    return (up ? 0x01 : 0) | (uv ? 0x04 : 0) | 0x08 | 0x10 | (at ? 0x40 : 0);
  }

  #counterBytes(n) { return new Uint8Array([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]); }

  /** navigator.credentials.create() → the JSON the browser module sends. */
  async create(options, origin, { uv = true, rpId = options.rp.id, type = 'webauthn.create', challenge = options.challenge } = {}) {
    this.keys = await crypto.subtle.generateKey(ALGS[this.alg].gen, true, ['sign', 'verify']);
    this.userHandle = options.user.id;
    const cd = utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
    const authData = concat(
      await sha256(utf8(rpId)),
      new Uint8Array([this.#flags({ uv, at: true })]),
      this.#counterBytes(this.counter ? this.count : 0),
      new Uint8Array(16), // AAGUID
      new Uint8Array([this.credId.length >> 8, this.credId.length & 255]),
      this.credId,
      cbor(await this.#coseKey()),
    );
    const att = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: this.id, rawId: this.id, type: 'public-key',
      response: { clientDataJSON: b64urlFromBytes(cd), attestationObject: b64urlFromBytes(att), transports: ['internal', 'hybrid'] },
    };
  }

  /** navigator.credentials.get() → the JSON the browser module sends. */
  async get(options, origin, { uv = true, rpId = options.rpId, challenge = options.challenge, count, tamper = false } = {}) {
    if (this.counter) this.count += 1;
    const c = count ?? (this.counter ? this.count : 0);
    const cd = utf8(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
    const authData = concat(await sha256(utf8(rpId)), new Uint8Array([this.#flags({ uv })]), this.#counterBytes(c));
    let sig = new Uint8Array(await crypto.subtle.sign(ALGS[this.alg].sign, this.keys.privateKey, concat(authData, await sha256(cd))));
    if (this.alg === -7) sig = rawToDer(sig);
    if (tamper) sig[sig.length - 1] ^= 1;
    return {
      id: this.id, rawId: this.id, type: 'public-key',
      response: { clientDataJSON: b64urlFromBytes(cd), authenticatorData: b64urlFromBytes(authData), signature: b64urlFromBytes(sig), userHandle: this.userHandle },
    };
  }
}
