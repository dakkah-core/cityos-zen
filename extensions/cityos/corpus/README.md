# Source-local preview corpus

`cart-quantity-preview.json` is a synthetic Zen policy document used only to
exercise the initial strict adapter. The `authorized` input is caller-supplied
test data and is not a verified identity or approval. The document is not an
Agora policy revision, a decision receipt, an owner contract, or production
evidence. Its safe-integer comparison is a bounded subset of the current Agora
`max_quantity` rule; it does not yet model SKU selection or owner transactions.

`s14-decision-baseline.json` describes synthetic inputs and expected results for
the recorded S14 TypeScript source blob. `scripts/corpus/verify-s14.test.mjs`
executes that actual implementation against every case and rejects source drift.
This characterizes only the pure capability-pack resolver; it does not test
receipt signing, disclosure, currentness, persistence or owner authorization.
The pure resolver currently treats an unparseable consent expiry as absent in
the `legacy-invalid-consent-expiry` case. This is a characterization for owner
review, not an intended new authorization rule. The inspected S14 operation
receipt issuer separately rejects a non-finite consent expiry before calling the
resolver. This case does not establish a live authorization bypass.
The Rust `shared-policy-compat_rust` comparison profile accepts strict UTC
timestamps only; `verify-s14-rust.test.mjs` checks the same corpus and records
both the invalid-clock and invalid-consent cases as unsupported rather than
claiming general JavaScript `Date.parse` parity.

`agora-cart-baseline.json` captures synthetic owner-rule examples for the
recorded Agora source blob. `scripts/corpus/verify-agora.test.ts` executes the
actual owner use case with only the storage boundary replaced by fixture data.
It characterizes the standalone evaluator, not cart mutation enforcement.

`receipt-source-baseline.json` pins the currently inspected issuer, domain,
canonicalization, fixture and test source blobs. `verify-receipt-sources.test.mjs`
checks those pins. The source-only Vitest configuration prevents ignored stale
JavaScript beside the authored TypeScript from shadowing the intended source.
The existing receipt suites use synthetic owners and storage; they are not a
database, deployed issuer or Rust wire-compatibility proof.
