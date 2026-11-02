# CityOS Zen extension

This independent Cargo workspace contains the CityOS-owned integration with Zen.
It is not a policy issuer, an owner authority, or a production activation
record. The current `cart-quantity-preview` profile is deliberately restricted
to synthetic preview data. It is not a qualified authoritative policy profile.

The worker exits unavailable by default. Its explicitly selected
`--preview-stdio` mode is a bounded-input, non-authoritative cart preview;
it does not install operating-system isolation or enforce a deadline. The Linux
supervised preview adds a deadline and per-process restrictions, but is not a
sandbox or a credential boundary. Do not route an owner action through any
preview. Fact provenance, receipt issuance and owner enforcement are outside
these previews.

The supervised cart and experimental network preview retain their existing
stdout behavior, including terminal and regular-file destinations; their final
stdout write and error messages can block. The supervised S14 mode instead
requires stdout to be a stable, write-only anonymous Linux pipe and a trusted,
accessible procfs that permits reopening that pipe for writing. Merely holding
the inherited descriptor does not guarantee permission to reopen it. It fails
closed for terminals, regular files, sockets, named FIFOs, a stdout writer with
`O_DIRECT` (packet mode), or a failed procfs reopen, and emits no diagnostic on
inherited stderr. Its nonblocking forwarding preserves the inherited descriptor
flags and shares the collection deadline; it assumes the descriptor and its flags are not changed
concurrently. Other pipe writers can independently write or use packet mode.

Cleanup signals the process group and direct child, and normally reaps the
direct child before forwarding. If it does not exit within a short cleanup
grace period, a background reaper can run only while the supervisor remains
alive; descendants that escape the group are not contained. Neither the
deadline nor the cleanup grace is a hard wall-clock guarantee against kernel
stalls or scheduling delays.

The fixed S14 consent gate has a separate `--s14-consent-preview-stdio` mode and,
on supported Linux targets, `--supervised-s14-consent-preview-stdio`. Each
accepts one JSON object on stdin followed by EOF, for example:

```json
{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"granted","expiresAtMillis":1788220920000},"nowMillis":1788220860000}}
```

`consent` is either `{"state":"missing-or-not-granted"}` or a `granted`
state with an explicit `expiresAtMillis` integer or `null`. Times are exact
integer milliseconds in the ECMAScript Date range. The caller must validate
all original expiry strings, complete S14's earlier checks and rule matching,
and normalize non-granted states before sending facts. The result is exactly
`{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543"}`
or the same object with `"outcome":"consent-not-granted"`. A satisfied gate
is not an authorization. `sourceSha256` identifies the admitted fixed preview
source; it is emitted only after successful evaluation and source identity
verification. Errors produce no result. The supervised mode validates the
exact source identity and response and fails closed on worker failure or
timeout; it does not establish a qualified isolation profile.

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
