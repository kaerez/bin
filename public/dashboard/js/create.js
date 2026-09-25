// create.js — the dashboard's composer entry: the shared composer
// (public/js/composer.js) for the signed-in account.
import '../../js/kdf-progress.js';
import { startComposer } from '../../js/composer.js';
import { createNote, initFileShare, uploadChunk, finalizeFileShare, deleteShare } from '../../js/api.js';
import { ready } from './nav.js';

startComposer(await ready, { createNote, initFileShare, uploadChunk, finalizeFileShare, deleteShare });
