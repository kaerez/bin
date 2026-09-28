// drivepolicy.js — the role's file-type rules (fileTypeMode / fileTypeRules,
// public/js/filepolicy.js) for what goes into a Drive: an upload and a file
// taken in from a Receive link. As for file shares, the Worker never reads the
// file: the browser declares the file's { ext, mime } (from the name and type
// it seals) when a type policy applies, and the declaration is checked here and
// never stored. A modified client could lie; the declaration makes the policy
// enforceable for honest clients (SECURITY.md, "File policy"). The folder-depth
// limit needs no declaration: the Drive knows its own tree (src/drive-do.js).

import { err } from './http.js';
import { checkDeclaredTypes, refusedTypes, describeType } from '../../public/js/filepolicy.js';

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
