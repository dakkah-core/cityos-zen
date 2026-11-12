# CityOS repository agent instructions: cityos-zen

## CityOS repository federation

Before changing behavior, identify its registered source owner. This checkout is an independent source home; directory names, sibling checkouts, migration copies, generated projections, or dependencies do not transfer ownership. The target boundaries below guide placement, while current owner records govern actual transfers:

- `dakkah-cityos-cms` is the legacy transition donor. CMS domain/backend work targets `cityos-core-cms`; Engineering services and compiler backends target `cityos-engineering`; shared.policy targets `cityos-shared-policy`; Agora behavior stays in `cityos-core-agora`.
- `cityos-core-nexus` has a Rust-primary source target under ADR-NEXUS-0013. Go and Python services require registered owner contracts, and existing implementations remain selected until qualified consumer cutover. Tryton vendor integration remains Python. `cityos-zen` is the upstream-connected fork-maintenance repository; `cityos-shared-policy` consumes Zen as a pinned `vendor/zen` submodule and keeps CityOS extensions outside upstream-owned paths.
- Backend behavior uses Rust, Go, Python, or the required vendor runtime according to the owning system. CMS and Agora may be Rust-first, with Go/Python integrations where needed. TypeScript remains for web/front-end clients; do not add TypeScript backend business logic unless a current owner decision explicitly permits it during migration.

Keep existing CMS behavior until its owner-specific transfer, contract parity, migration/reconciliation, consumer adoption, rollback, and cutover evidence are complete. Target direction alone transfers no source authority or authorizes deletion, activation, or cutover. For cross-repository work, edit each owning repository and use versioned artifacts; do not rely on mutable sibling checkouts. Preserve independent Git histories and unrelated work.


## Upstream fork role

This repository maintains the CityOS fork connected to `gorules/zen`. Keep the upstream remote and genuine merge ancestry. The shared.policy product and its CityOS runtime belong in `cityos-shared-policy`, which consumes this fork as a pinned `vendor/zen` submodule. Keep CityOS fork extensions under the protected `extensions/cityos` path, separate from upstream-owned core. Make policy-specific domain, host, persistence, and management code in the Policy repo; change Zen core only for a qualified public API gap recorded by the Policy patch ledger.

## Upstream preservation invariants

Preserve origin as the CityOS fork and upstream as gorules/zen. Record the exact integrated upstream commit in the trusted integration manifest and retain genuine merge ancestry. Before integrating upstream changes, reject unexpected repository or source identity, unqualified source state, protected-path deletion, rename or mode changes, symlink escapes, and incoming upstream collisions with CityOS-owned extensions/cityos. Run the preservation checker and required fork and consumer qualification against the exact candidate. Keep CityOS extensions under extensions/cityos and separate from upstream-owned core. Do not use blanket merge=ours rules or hide core divergence.

## Compiler and generated-output verification

For changes to a compiler, generator, template, generated code, or its consuming application:
- Validate canonical inputs and semantic rules before generation. Generate from explicit, pinned inputs into a clean destination and retain a manifest linking outputs to their inputs and templates.
- Run the native compiler, type checker, and linter for each emitted language, including selected consuming applications and handwritten extension points.
- Run Semgrep CE on explicit source and output paths with metrics disabled and reviewed local rules. Record tool and ruleset versions, scanned paths, exclusions, and findings; keep positive and negative fixtures for CityOS rules.
- Run selected Skylos checks with uploads, cloud, and AI modes disabled. Record the tool version, checks, scope, and coverage. Treat unqualified findings as review leads until the check has positive and negative fixtures and an owner-reviewed policy.
- Report exact commands and results. Zero-file, partial, or skipped required coverage is not a clean pass; scanner output alone does not prove security or behavior.
