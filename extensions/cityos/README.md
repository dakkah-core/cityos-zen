# CityOS Zen extension

This independent Cargo workspace contains the CityOS-owned integration with Zen.
It is not a policy issuer, an owner authority, or a production activation
record. The current `cart-quantity-preview` profile is deliberately restricted
to synthetic preview data. It is not a qualified authoritative policy profile.

The worker exits unavailable by default. Its explicitly selected
`--preview-stdio` mode is a bounded-input, non-authoritative preview transport;
it does not install operating-system isolation or enforce a deadline. Do not
route an owner action through it or the in-process preview. Worker isolation,
resource limits, fact provenance, receipt issuance and owner enforcement have
not yet been implemented.

Use the workspace toolchain projection and its own lockfile. Validate the
projection against `rust/rust-toolchain.toml` in the owning CMS checkout before
claiming toolchain parity. The upstream lockfile and each consumer lockfile
represent separate dependency closures and require their own qualification.

From `extensions/cityos`:

```text
cargo +1.98.1 test --locked --workspace
cargo +1.98.1 fmt --all -- --check
python -m unittest discover -s ../../scripts/upstream -p 'test_*.py' -v
python ../../scripts/upstream/check_toolchain.py --cms <path-to-cms-checkout>
```

From the CMS checkout, after its Node selector and exact-version check:

```powershell
$env:CITYOS_CMS_ROOT = (Get-Location).Path
node --test C:/cityos/cityos-zen/scripts/corpus/verify-s14.test.mjs C:/cityos/cityos-zen/scripts/corpus/verify-receipt-sources.test.mjs
node node_modules/vitest/vitest.mjs run --config C:/cityos/cityos-zen/scripts/corpus/vitest-s14.config.mjs --root packages/shared-policy-application src/operation-receipt.test.ts src/operation-receipt-security.test.ts
node node_modules/vitest/vitest.mjs run --config C:/cityos/dakkah-cityos-cms/packages/agora-demand-commitment-application/vitest.config.ts --root C:/cityos/cityos-zen scripts/corpus/verify-agora.test.ts
```

The corpus runners check recorded CMS source blobs and use synthetic inputs.
They do not establish integration with a deployed S14 or Agora owner.
