# CityOS Zen upstream maintenance

`origin` is the CityOS fork and `upstream` is `gorules/zen`. The integrated
upstream commit and CityOS-owned paths are recorded in
`config/upstream/integration.json`. Preserve real Git merge ancestry.

Before an update, capture the trusted CityOS base and exact upstream candidate.
Run the checker from the trusted base against the proposed commit, inspect its
ledger and upstream delta, and resolve every owned-path collision. A routine
update may not silently alter protected controls or remove an existing ledger
invariant. Changes to those controls require a separately reviewed trusted-control
transition; candidate code cannot authorize its own weaker checks.
Fetch `master` from the allowlisted upstream into `refs/remotes/upstream/master`
before checking; the selected commit must be reachable from that fetched ref.
A locally stale or locally rewritten tracking ref is not authenticated evidence.
The trusted PR workflow fetches the ref itself and runs only the base revision's
checker with read-only permissions. Candidate build and regression code runs in
a separate ordinary pull-request workflow without publication credentials.
New upstream-owned patch paths require a reviewed control transition before the
candidate checker will accept code on those paths. This conservative rule can
block a necessary bridge until an independent trusted transition is established;
the source checker must not be bypassed by self-declaring the patch.

After the source boundary passes, run upstream, extension, isolation and actual
consumer qualification against the selected artifact. Source merge, publication,
consumer adoption and activation are separate events. The source check and this
document are not evidence of remotely configured branch protections or runtime
qualification.

The initial installation starts from the recorded upstream-only commit. Its
bootstrap necessarily executes candidate controls because no earlier CityOS
checker exists; it requires independent review and does not itself establish a
trusted historical control. A base-controlled PR workflow cannot run before
its first installation on the base branch. Initial bootstrap therefore needs an
independent review and a separately enforced check; this file does not establish
the repository hosting rules that require the subsequent checks.

Inherited release jobs are restricted to `gorules/zen`; CityOS publication needs
its own admitted namespace, workflow, provenance and authorization.
