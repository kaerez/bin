// drive.js — the Drive page's entry (/dashboard/drive/): the signed-in
// profile, the Drive client (public/js/driveclient.js), then the page itself
// (drive-app.js).
import '../../js/kdf-progress.js';
import { revokeShare } from '../../js/api.js';
import { h, friendlyError } from '../../js/common.js';
import { ready } from './nav.js';
import { startDrive } from './drive-app.js';

const mount = document.getElementById('drive-root');
const profile = await ready;
let drive;
try {
  drive = await import('../../js/driveclient.js');
} catch (e) {
  drive = null;
  mount.replaceChildren(h('p.msg.error', { role: 'alert', text: `The Drive is unavailable right now: ${friendlyError(e)}` }));
}
if (drive) {
  // The profile names the account, so the client needs no session lookup; while
  // the owner acts as a user, the server hands this page the user's KEKs (in its memory only).
  const user = { id: profile.user.id, role: profile.user.role, impersonating: !!profile.impersonatedBy };
  startDrive(mount, { drive, profile, user, revoke: revokeShare });
}
