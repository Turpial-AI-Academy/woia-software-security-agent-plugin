# Security Review Method

## Objective

Produce defensible, candidate-bound security evidence for a software release decision. The review is independent: do not assume an implementation is secure because it passed earlier design, code review, testing, or QA phases.

## 1. Candidate anchor

Record before analysis:

- repository/component;
- commit SHA and tree SHA when available;
- version/build/artifact identifier;
- QA approval reference;
- deployment target and environment;
- review timestamp/context;
- reviewer/tool versions when material.

If the candidate changes, identify whether changed files/configuration/dependencies can affect reviewed attack surfaces. Re-run affected security evidence rather than carrying PASS forward automatically.

## 2. Evidence hierarchy

Prefer evidence in this order:

1. directly observed code/config/runtime behavior;
2. reproducible tests and scanner output tied to the candidate;
3. signed/immutable build, dependency, and artifact metadata;
4. repository documentation and threat models;
5. operator statements and assumptions.

Documentation is intent unless implementation evidence confirms it.

## 3. Discovery inventory

Inventory only what can matter to the candidate:

- entry points and externally reachable interfaces;
- identities, roles, tenants, service accounts, approvals, and administrative paths;
- data classes, secrets, credentials, tokens, keys, and sensitive configuration;
- filesystem reads/writes, generated files, uploads/downloads, temporary paths, symlinks;
- network destinations, webhooks, callbacks, redirects, private ranges, proxies;
- databases, queries, templates, parsers, serialization formats;
- tools, agents, plugins, MCP servers, scripts, shell/process execution;
- queues, retries, locks, idempotency keys, effect receipts, reconciliation;
- dependencies, lockfiles, registries, build inputs, images, artifacts, update channels;
- logs, traces, metrics, diagnostics, audit records, support/admin tooling;
- backups, restore paths, incident controls, feature flags, and emergency access.

## 4. Review lenses

### Secrets and authority

Check that secrets are referenced rather than copied into source/model/logs, scopes are minimal, production credentials are separated, and possession of a credential is not confused with business authority.

### Authentication, authorization, tenancy, approvals

Trace identity from ingress to effect. Check object/tenant scoping, privilege boundaries, default-deny behavior, approval target/payload binding, expiry/revocation, and administrative bypasses.

### Untrusted input and injection

Treat files, documents, webpages, package metadata, model/tool output, and external messages as untrusted data. Review command/shell injection, path traversal, SSRF, query injection, template injection, XML/entity risks, unsafe deserialization, spreadsheet/CSV formula injection, prompt/tool injection, and output-to-instruction confusion as applicable.

### External effects and state

For side effects, inspect idempotency, persist-before-network patterns where required, retries, timeout ambiguity, duplicate suppression, locks/sequence, compensation, and reconciliation. A timeout may mean `unknown`, not `failed`.

### Filesystem and execution

Review canonicalization, authorized roots, symlinks/junctions, TOCTOU, executable provenance, working directory, environment inheritance, temporary files, permissions, cleanup, and sandbox/container boundaries.

### Network and remote services

Review egress policy, URL/scheme/port restrictions, DNS/redirect handling, localhost/metadata/private range exposure, TLS/service identity, rate/size limits, data residency, and remote tool/server trust.

### Observability and audit

Ensure logs/traces minimize secrets and personal/sensitive data, effects and denials leave sufficient evidence, audit records cannot be silently rewritten by the same path under review, and diagnostic bundles respect classification.

### Supply chain

Review exact versions/digests, dependency provenance, lockfiles, namespace/confusion exposure, install/update scripts, package/plugin/MCP identity, container base images, generated artifacts, advisories, SBOM availability, and rollback.

### Operations and recovery

Review production fail-closed behavior, environment separation, break-glass controls, backups/restore tests, incident containment, credential rotation, admin tooling, and security-sensitive manual procedures.

## 5. Proportionate depth

Depth follows risk. Increase scrutiny when the candidate:

- handles sensitive or regulated data;
- performs irreversible/high-value external effects;
- changes authentication/authorization/approval logic;
- changes exposed network surfaces;
- adds execution, plugins, MCP/tools, or broad filesystem/network authority;
- changes cryptography/secrets handling;
- changes supply-chain/build/publish paths;
- fixes a previous security incident or P0/P1 finding.

For low-risk changes, explicitly record why a surface is not applicable rather than running heavy tooling by ritual.

### Bounded follow-up and evidence lifecycle

For an external report metadata or explanatory-documentation correction, use the existing healthy review and threat map when the exact production candidate, attack surface, findings, controls, acceptance, and security decisions are unchanged. Inspect only the affected claim and its owning source, preserve unrelated valid records, and re-check candidate identity, blocking-risk status, required scope coverage, and acceptance conditions/validity.

Independently inspect durable records of actual execution or direct observation before reuse. Confirm candidate, scope, environment, relevant configuration, provenance, and freshness. A prior agent summary or assumption is not proof. Missing required execution evidence requires the relevant check, or an explicit BLOCKED/INCOMPLETE decision when it cannot be obtained.

Record reusable proof, invalidated checks/findings/acceptance, fresh validation still needed, and assumptions separately. Invalidation follows demonstrated impact rather than a new session. A changed candidate requires a new candidate-bound decision; evidence is retained only when its continued applicability is independently established. Advisory changes, expired acceptance, control drift, and changed deployment assumptions can invalidate security evidence without a source mutation.

New reviews, candidate/artifact changes, public contracts, persisted state/migrations, trust/auth/secrets boundaries, supply chain, deployment/recovery, provider dependencies, missing proof, and contradictions require deeper review of the affected risk. Load the reference for that concern; do not replay all historical context or unrelated tooling by default.

## 6. Independence and correction

When a finding is confirmed:

1. reproduce the causal path;
2. identify the security invariant that failed;
3. fix the narrow cause, not just the symptom;
4. add regression evidence where recurrence is plausible;
5. re-run the minimum affected evidence plus any newly exposed surface;
6. retain the original finding and mark its disposition—do not erase history.

## 7. Completion

A review is complete only when candidate identity, scope, findings, executed evidence, skipped checks, residual risk, and gate decision are all explicit.
