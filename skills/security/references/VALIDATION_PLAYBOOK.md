# Validation Playbook

Choose checks from the actual stack and threat model. No specific scanner is mandatory merely because it is popular.

## Baseline checks

When applicable:

- repository-native security tests;
- secret scan over tracked source, configuration, history/diff as policy requires, and release payload;
- static analysis/SAST or focused semantic code review;
- dependency/advisory and lockfile review;
- SBOM/provenance inspection;
- container/image and infrastructure configuration review;
- exposed endpoint/authz tests;
- policy/approval/tenant boundary tests;
- negative input/injection tests;
- filesystem/path/symlink tests;
- network/SSRF/redirect tests;
- concurrency/idempotency/retry/reconciliation tests;
- logging/redaction/audit tests;
- backup/restore or recovery evidence;
- release artifact/digest/source identity verification.

## Adversarial testing

Prefer synthetic fixtures and non-production targets.

Useful classes:

- unauthorized identity/role/tenant;
- stale/replayed approval or token;
- changed target/payload after approval;
- malformed/extreme input;
- hostile document/tool output;
- encoded traversal and symlink/junction cases;
- localhost/private/metadata URL targets and redirect chains;
- duplicate requests and concurrent execution;
- timeout after a possibly successful external effect;
- dependency/package substitution;
- missing/disabled security dependency;
- log/error paths containing sensitive fields;
- production flag/environment misconfiguration.

Use fuzz/property testing when invariants can be expressed mechanically and the input space is broad.

## Manual searches

Automated tools often miss architectural bypasses. Search manually for:

- direct calls to privileged providers/services that bypass policy wrappers;
- `production=true`, debug/admin flags, break-glass code, broad allowlists;
- retries around non-idempotent effects;
- logging of environment variables, credentials, private keys, tokens, request bodies, or PII;
- shell/process construction and unsafe interpolation;
- generic HTTP/SQL/filesystem tools in privileged paths;
- authorization checks after data/effect access rather than before it;
- hidden fallback paths when auth/policy/scanner/sandbox is unavailable;
- unpinned dependencies/images/plugins and dynamic install/update behavior.

## Tool result handling

For each tool record:

- tool and version;
- configuration/ruleset when material;
- candidate/ref scanned;
- scope/exclusions;
- result;
- failures/timeouts;
- whether findings were manually verified.

Do not convert tool severity directly into release severity without context.

## Remediation verification

For every remediated P0/P1, and any other blocking finding:

1. reproduce the original failure before fix when safe/available;
2. identify the regression assertion;
3. run it on the fixed candidate;
4. verify no compensating control was weakened;
5. re-run affected adjacent checks;
6. record exact evidence.

## Handling unavailable checks

If a scanner or environment is unavailable:

- do not label it PASS;
- state why it is unavailable;
- perform alternative evidence where meaningful;
- assess whether the uncertainty itself blocks release.

A tool outage does not automatically block; missing evidence for a high-risk boundary may.

## Stop conditions

Stop effects and escalate instead of probing further when testing could:

- expose real customer/regulated data;
- trigger destructive production effects;
- access data without authorization;
- disrupt real systems;
- rotate/revoke production credentials;
- publish exploitable details.

Use local/synthetic fixtures, sandbox, staging, or explicit human authorization for destructive security testing.
