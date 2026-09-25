// passkeys.js — the browser side of WebAuthn: turn the server's JSON options
// into navigator.credentials calls and the resulting credential back into
// JSON (binary fields as base64url). The server checks everything
// (src/lib/webauthn.js); this module only moves bytes.

import { b64urlFromBytes, bytesFromB64url } from './bytes.js';

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

/** Create a passkey from the server's creation options → credential JSON. */
export async function createPasskey(o) {
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        ...o,
        challenge: buf(o.challenge),
        user: { ...o.user, id: buf(o.user.id) },
        excludeCredentials: descriptors(o.excludeCredentials),
      },
    });
  } catch (e) { throw explain(e); }
  if (!cred) throw new Error('No passkey was created.');
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64(r.clientDataJSON),
      attestationObject: b64(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
  };
}

/** Use a passkey for the server's request options → assertion JSON. */
export async function usePasskey(o, { signal } = {}) {
  let cred;
  try {
    cred = await navigator.credentials.get({
      publicKey: { ...o, challenge: buf(o.challenge), allowCredentials: descriptors(o.allowCredentials) },
      ...(signal ? { signal } : {}),
    });
  } catch (e) { throw explain(e); }
  if (!cred) throw new Error('No passkey was used.');
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64(r.clientDataJSON),
      authenticatorData: b64(r.authenticatorData),
      signature: b64(r.signature),
      userHandle: b64(r.userHandle),
    },
  };
}
