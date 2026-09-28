// confirm.js — "confirm it's you" for changes to one's own account and for
// the owner's security settings: the password typed into a field (cleared at
// once, so every change asks again) or, when the field is empty and the
// account has a passkey, a fresh passkey check. The server verifies either
// (src/routes/stepup.js); this only builds the { current } / { reauth } part.

import { prelogin, reauthOptions, myPasskeys } from '../../js/api.js';
import { stretch } from '../../js/pwauth.js';
import { passkeysSupported, usePasskey, usePasskeyPrf } from '../../js/passkeys.js';

/** Whether this browser and account can confirm with a passkey. */
export async function canUsePasskey() {
  if (!passkeysSupported()) return false;
  try {
    const st = await myPasskeys();
    return st.mode !== 'off' && st.passkeys.length > 0;
  } catch {
    return false;
  }
}

/** The label text for a confirmation field. */
export const confirmLabel = (text, passkey) => (passkey ? `${text}, or leave it empty to confirm with a passkey` : text);

/**
 * The confirmation for one change, from `input` (a password field) for
 * `username`; `passkey` says whether an empty field means "use a passkey".
 * `prfSalt` / `onPrf`: a passkey confirmation also asks for the PRF output
 * for that salt (the Drive's), handed to `onPrf({ prf, credentialId })` and
 * never sent (the password change opens the Drive key with it).
 */
export async function confirmStep(input, username, passkey, { prfSalt = null, onPrf = null } = {}) {
  const pw = input.value;
  input.value = '';
  if (pw) {
    const { salt, t } = await prelogin(username);
    return { current: await stretch(pw, salt, t) };
  }
  if (passkey && passkeysSupported()) {
    const o = await reauthOptions();
    if (prfSalt) {
      const { credential, prf } = await usePasskeyPrf(o.publicKey, prfSalt);
      if (prf && onPrf) onPrf({ prf, credentialId: credential.rawId });
      return { reauth: { challengeId: o.challengeId, credential } };
    }
    return { reauth: { challengeId: o.challengeId, credential: await usePasskey(o.publicKey) } };
  }
  throw new Error(passkey ? 'Enter your password, or leave it empty and confirm with a passkey.' : 'Enter your current password.');
}
