// drivepolicy.js — the role's file-type rules (fileTypeMode / fileTypeRules,
// public/js/filepolicy.js) for what goes into a Drive: an upload and a file
// taken in from a Receive link. When a type policy applies, the browser
// declares the file's { ext, mime } (from the name and type it seals), checked
// first (driveTypeRefusal) and never stored. Then, because the Worker opens a
// new item's sealed name and metadata anyway (src/lib/mek.js checkNewItem),
// the rule is enforced on what is stored (sealedTypeRefusal): the name's
// extension and the metadata's MIME type, with the same rule function, and the
// declaration must agree with them. A client that declares a false type is
// refused. The opened values stay in memory, are never logged or returned,
// and are zeroed right after. The folder-depth limit needs no declaration:
// the Drive knows its own tree (src/drive-do.js).

import { err } from './http.js';
import { checkDeclaredTypes, refusedTypes, describeType, fileExt, uncheckableExt } from '../../public/js/filepolicy.js';
import { fromUtf8 } from '../../public/js/bytes.js';

// As filepolicy.js checkDeclaredTypes: a MIME type a declaration can hold.
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

/** Does `policy` (Directory driveAccess().policy) restrict file types? */
export const typedPolicy = (policy) => !!policy && (policy.mode === 'allow' || policy.mode === 'block');

/**
 * Check one file's declared type (`declared`: the request's `types`, a list of
 * exactly one { ext, mime }) against the role's policy → null (allowed, or no
 * type policy) or the refusal: `400 declaration_required` (with the policy, so
 * the browser can check and declare), `400 invalid_declaration`, `403
 * file_type_not_allowed` (with the refused type). `what`: the action in the
 * refusal ("uploaded to", "added to").
 */
export function driveTypeRefusal(policy, declared, what = 'uploaded to') {
  if (!typedPolicy(policy)) return null;
  if (declared === undefined) {
    return err(400, 'declaration_required', 'Your role has a file-type policy: declare the file’s type.', {
      policy: { mode: policy.mode, rules: policy.rules, maxFolderDepth: policy.maxFolderDepth },
    });
  }
  // Exactly one type: an empty list would match no rule, and so pass an allow list.
  const types = checkDeclaredTypes(declared);
  if (!types || types.length !== 1) return err(400, 'invalid_declaration', 'Invalid file type declaration: declare the file’s one { ext, mime }.');
  const refused = refusedTypes(policy.mode, policy.rules, types);
  if (refused.length) return err(403, 'file_type_not_allowed', `This file type may not be ${what} your Drive: ${describeType(refused[0])}.`, { refused });
  return null;
}

/**
 * The rule on what is stored: `name` and `meta` are the opened (plaintext)
 * bytes of the item's sealed name and metadata (checkNewItem's `inspect`),
 * `declared` the request's `types` (already checked by driveTypeRefusal).
 * The file's type is { ext of the name, mime of the metadata's `type` }, as
 * the browser declares it (filepolicy.js declare). → null or the refusal:
 * `403 file_type_not_allowed` when the rules refuse the stored type, when it
 * cannot be checked (an extension a declaration cannot hold, metadata without a
 * valid type), or when the declaration does not match it. The refusal names
 * the rule's verdict, never the file's name or the stored type.
 */
export function sealedTypeRefusal(policy, name, meta, declared, what = 'uploaded to') {
  if (!typedPolicy(policy)) return null;
  const refuse = (message) => err(403, 'file_type_not_allowed', message);
  let t;
  try {
    const n = fromUtf8(name);
    const m = meta ? JSON.parse(fromUtf8(meta)) : null;
    const mime = m && typeof m === 'object' && typeof m.type === 'string' ? m.type.toLowerCase() : null;
    if (uncheckableExt(n) || !mime || !MIME_RE.test(mime)) return refuse(`This file’s type cannot be checked against your role’s file-type rules, so it may not be ${what} your Drive.`);
    t = { ext: fileExt(n), mime };
  } catch {
    return refuse(`This file’s type cannot be checked against your role’s file-type rules, so it may not be ${what} your Drive.`);
  }
  const d = checkDeclaredTypes(declared);
  if (d && (d.length !== 1 || d[0].ext !== t.ext || d[0].mime !== t.mime)) return refuse(`The declared file type does not match the file’s stored type, so it may not be ${what} your Drive.`);
  if (refusedTypes(policy.mode, policy.rules, [t]).length) return refuse(`This file type may not be ${what} your Drive.`);
  return null;
}
