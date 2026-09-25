## Summary

What does this change and why?

## Checklist

- [ ] `npm run lint` passes
- [ ] `npm test` passes (all suites green)
- [ ] Crypto/format/AAD changes (if any) updated [`SPEC.md`](./SPEC.md) **first** and regenerated
      the frozen vectors with `node test/genvectors.mjs` (never hand-edited) and cross-checked them
      with `python tools/verify-vectors.py`
- [ ] New behavior has test coverage
- [ ] No secrets, real share URLs, key fragments, API keys or `.dev.vars` committed

## Notes for reviewers
