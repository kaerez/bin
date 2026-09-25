// delete — remove a note or file share with its delete token. The token is
// supplied via --token-env or a hidden prompt (never a bare flag value, so it
// can't land in shell history/ps) and is sent only in the X-Delete-Token
// header (SPEC.md §10). Needs no API key: the token is the capability.
//
// --now: "delete now" as a recipient, when the sender allowed it. It needs
// the full share URL (with its #fragment) and the password, if any, instead
// of the token: the same two access proofs as opening, derived locally. No
// view is spent.
import { parseArgs } from 'node:util';
import { deriveAccess } from '../../vendor/crypto.js';
import { validateHead } from '../../vendor/format.js';
import { Client } from '../client.js';
import { UsageError } from '../errors.js';
import { resolveSecret } from '../secret.js';
import { kindOf, parseShareUrl, parseUrlOrId } from '../url.js';

const OPTIONS = {
  'token-env': { type: 'string' },
  server: { type: 'string', short: 's' },
  now: { type: 'boolean', default: false },
  'password-env': { type: 'string' },
};

async function deleteNow(raw, values, io) {
  if (values['token-env'] !== undefined || values.server !== undefined) {
    throw new UsageError('--now uses the share URL itself: it takes no --token-env or --server');
  }
  const { server, id, fragment } = parseShareUrl(raw);
  const kind = kindOf(id);
  const client = new Client(server, io.fetch);
  const head = validateHead(await client.head(kind, id));
  if (head.meta.deletable !== true) {
    throw new UsageError('the sender did not allow recipients to delete this share (use the delete token instead)');
  }
  let password = await resolveSecret({ envVar: values['password-env'], promptWanted: false, io });
  if (head.adata.kdf === 'argon2id-hkdf' && password === '') {
    if (!io.stdinIsTTY) throw new UsageError('this share is password-protected — pass it with --password-env <VAR>');
    password = await io.promptHidden('Password: ');
  }
  await client.expireShare(kind, id, await deriveAccess({ adata: head.adata, fragment, password }));
  io.stderr(`deleted ${id}\n`);
  return 0;
}

export async function cmdDelete(args, io) {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (e) {
    throw new UsageError(e.message);
  }
  if (positionals.length !== 1) {
    throw new UsageError('usage: secbin delete <share-url | id>  ·  secbin delete --now <share-url | ->');
  }
  if (values.now) {
    let raw = positionals[0];
    if (raw === '-') {
      raw = (await io.readStdin()).toString('utf8').trim();
      if (!raw) throw new UsageError('no share URL on stdin');
    }
    return deleteNow(raw, values, io);
  }
  if (values['password-env'] !== undefined) throw new UsageError('--password-env applies to --now only');

  // A share URL carries its own origin; a bare id needs --server / SECBIN_SERVER.
  const { server, id } = parseUrlOrId(positionals[0], values.server ?? io.env.SECBIN_SERVER);

  const token = await resolveSecret({
    envVar: values['token-env'],
    promptWanted: true,
    promptLabel: 'Delete token: ',
    io,
  });

  const client = new Client(server, io.fetch);
  await client.deleteShare(kindOf(id), id, token);
  io.stderr(`deleted ${id}\n`);
  return 0;
}
