// passkeys.js — the browser side of WebAuthn: turn the server's JSON options
// into navigator.credentials calls and the resulting credential back into
// JSON (binary fields as base64url). The server checks everything
// (src/lib/webauthn.js); this module only moves bytes. The *Prf variants also
// ask for the PRF extension (the Drive's passkey wraps, docs/DRIVE.md §3).

import { b64urlFromBytes, bytesFromB64url, randomBytes } from './bytes.js';

/** Can this browser use passkeys at all? */
export const passkeysSupported = () => typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function'
  && !!navigator.credentials && typeof navigator.credentials.create === 'function';

const buf = (s) => bytesFromB64url(s);
const b64 = (ab) => (ab ? b64urlFromBytes(new Uint8Array(ab)) : null);
const descriptors = (list) => (list || []).map((c) => ({ type: 'public-key', id: buf(c.id), ...(c.transports?.length ? { transports: c.transports } : {}) }));

/** Friendlier messages for what browsers throw (cancel, timeout, wrong device…). */
function explain(e) {
  if (e && e.name === 'NotAllowedError') return new Error('The passkey request was cancelled or timed out.');
  if (e && e.name === 'InvalidStateError') return new Error('This device already holds a passkey for your account.');
  if (e && e.name === 'SecurityError') return new Error('Passkeys need this site to be opened at its own address over HTTPS.');
  if (e && e.name === 'NotSupportedError') return new Error('This device cannot create a suitable passkey.');
  return e instanceof Error ? e : new Error('The passkey request failed.');
}

/** The PRF extension's output for `first`, as bytes, or null (not supported / not evaluated). */
function prfResult(cred) {
  try {
    const r = typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : null;
    const first = r && r.prf && r.prf.results && r.prf.results.first;
    if (first instanceof ArrayBuffer) return new Uint8Array(first.slice(0));
    if (ArrayBuffer.isView(first)) return new Uint8Array(first.buffer, first.byteOffset, first.byteLength).slice();
  } catch { /* no extension results */ }
  return null;
}

const prfExtension = (salt) => (salt ? { extensions: { prf: { eval: { first: salt } } } } : {});

async function create(o, prfSalt) {
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        ...o,
        challenge: buf(o.challenge),
        user: { ...o.user, id: buf(o.user.id) },
        excludeCredentials: descriptors(o.excludeCredentials),
        ...prfExtension(prfSalt),
      },
    });
  } catch (e) { throw explain(e); }
  if (!cred) throw new Error('No passkey was created.');
  const r = cred.response;
  return {
    credential: {
      id: cred.id,
      rawId: b64(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: b64(r.clientDataJSON),
        attestationObject: b64(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
    },
    prf: prfSalt ? prfResult(cred) : null,
  };
}

async function get(o, { signal, prfSalt } = {}) {
  let cred;
  try {
    cred = await navigator.credentials.get({
      publicKey: { ...o, challenge: buf(o.challenge), allowCredentials: descriptors(o.allowCredentials), ...prfExtension(prfSalt) },
      ...(signal ? { signal } : {}),
    });
  } catch (e) { throw explain(e); }
  if (!cred) throw new Error('No passkey was used.');
  const r = cred.response;
  return {
    credential: {
      id: cred.id,
      rawId: b64(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: b64(r.clientDataJSON),
        authenticatorData: b64(r.authenticatorData),
        signature: b64(r.signature),
        userHandle: b64(r.userHandle),
      },
    },
    prf: prfSalt ? prfResult(cred) : null,
  };
}

/** Create a passkey from the server's creation options → credential JSON. */
export async function createPasskey(o) {
  return (await create(o)).credential;
}

/** Use a passkey for the server's request options → assertion JSON. */
export async function usePasskey(o, { signal } = {}) {
  return (await get(o, { signal })).credential;
}

/*
 * The same, also asking for the PRF extension's output for `prfSalt` →
 * { credential, prf } where `prf` is a Uint8Array, or null when the
 * authenticator has no PRF (or evaluates it only on use, not at creation).
 * `prf` is a secret: only `credential` ever goes to the server.
 */
export const createPasskeyPrf = (o, prfSalt) => create(o, prfSalt);
export const usePasskeyPrf = (o, prfSalt, { signal } = {}) => get(o, { signal, prfSalt });

/**
 * A local assertion only to read a passkey's PRF output (it goes to no
 * server, so its challenge is random and its signature never checked).
 * `credentialIds` (base64url) limits the choice to passkeys with a Drive
 * wrap → { credentialId, prf } (prf null without PRF support).
 */
export async function passkeyPrfOnly(prfSalt, credentialIds = []) {
  const { credential, prf } = await get({
    challenge: b64urlFromBytes(randomBytes(32)),
    userVerification: 'required',
    timeout: 120000,
    allowCredentials: credentialIds.map((id) => ({ id })),
  }, { prfSalt });
  return { credentialId: credential.rawId, prf };
}
