// drive.js — the Drive page's entry (/dashboard/drive/): the signed-in
// profile, the Drive client, then the page itself (drive-app.js).
//
// TEMPORARY: `?mock=1` loads the in-memory stand-in client
// (public/js/driveclient.mock.js) instead of the real one, for building and
// testing the page before the Drive client and server land. It is removed at
// integration together with that file.
import '../../js/kdf-progress.js';
import { revokeShare } from '../../js/api.js';
import { h, friendlyError } from '../../js/common.js';
import { ready } from './nav.js';
import { startDrive } from './drive-app.js';

const mount = document.getElementById('drive-root');
const profile = await ready;
const mock = new URLSearchParams(location.search).get('mock') === '1';
let drive;
try {
  drive = mock ? await import('../../js/driveclient.mock.js') : await import('../../js/driveclient.js');
} catch (e) {
  drive = null;
  mount.replaceChildren(h('p.msg.error', { role: 'alert', text: `The Drive is unavailable right now: ${friendlyError(e)}` }));
}
if (drive) {
  if (mock) { const a = document.getElementById('nav-drive'); if (a) a.hidden = false; }
  startDrive(mount, { drive, profile, revoke: mock && drive.revokeShare ? drive.revokeShare : revokeShare });
}
