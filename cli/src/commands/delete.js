// delete — remove a note or file share with its delete token. The token is
// supplied via --token-env or a hidden prompt (never a bare flag value, so it
// can't land in shell history/ps) and is sent only in the X-Delete-Token
// header (SPEC.md §10). Needs no API key: the token is the capability.
import { parseArgs } from 'node:util';
import { Client } from '../client.js';
import { UsageError } from '../errors.js';
import { resolveSecret } from '../secret.js';
import { kindOf, parseUrlOrId } from '../url.js';

const OPTIONS = {
  'token-env': { type: 'string' },
  server: { type: 'string', short: 's' },
};

export async function cmdDelete(args, io) {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (e) {
    throw new UsageError(e.message);
  }
  if (positionals.length !== 1) {
    throw new UsageError('usage: secbin delete <share-url | id>');
  }

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
