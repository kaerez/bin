// setup-records.js — for every workerd test file: a sign-in record written with a
// keyring but not sealed before its write throws (src/directory-do.js RECORDS),
// so any code path that skips #preseal fails a test instead of writing the
// entry in the clear for the pass, as production does.
import { RECORDS } from '../src/directory-do.js';

RECORDS.strict = true;
