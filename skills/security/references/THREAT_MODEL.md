# Threat Model

Use this as a reusable prompt for discovery, not as a claim that every threat applies to every repository.

## Assets

Identify what must be protected:

- credentials, secrets, tokens, keys;
- personal, customer, business, regulated, or proprietary data;
- source code, models, prompts, policies, configuration, and build inputs;
- authorization state, approvals, roles, tenant boundaries;
- money/value, messages, deployments, deletions, and other external effects;
- package/artifact integrity and provenance;
- audit evidence and operational continuity.

## Actors

Consider:

- unauthenticated external user;
- authenticated low-privilege user;
- cross-tenant user;
- malicious/compromised administrator or service identity;
- compromised dependency, package, image, plugin, skill, MCP server, webhook, or upstream service;
- malicious document/webpage/tool output or other indirect prompt-injection source;
- compromised CI/build/release environment;
- accidental operator error;
- attacker with partial filesystem/network access.

## Trust boundaries

Map relevant boundaries such as:

~~~text
User/client
<-> application/API
<-> identity/authorization
<-> business logic
<-> data stores
<-> queue/workers
<-> external services
<-> tools/plugins/MCP
<-> filesystem/process
<-> network
<-> build/package/release systems
<-> observability/audit
~~~

For each boundary record:

- identity and authentication;
- authorization/authority;
- data crossing it;
- effects it can trigger;
- secrets/credentials involved;
- validation/sanitization;
- logging/evidence;
- failure/timeout behavior.

## Threat families

### Identity and authority

- authentication bypass;
- broken object/tenant authorization;
- privilege escalation;
- confused deputy;
- approval spoofing or stale approval reuse;
- unsafe break-glass/admin path.

### Injection and untrusted content

- command/shell injection;
- path traversal/symlink escape;
- SSRF and unsafe redirects;
- SQL/query/template/XML/deserialization injection;
- CSV/spreadsheet formula injection;
- prompt injection and tool-output instruction confusion;
- malicious uploads/documents/resources.

### Secrets and data

- secret leakage into code, model context, logs, artifacts, diagnostics;
- excessive data exposure;
- insecure retention/export;
- weak isolation between environments/tenants;
- unencrypted or misdirected sensitive data where encryption/target binding is required.

### External effects and concurrency

- duplicate effects;
- unsafe retries;
- timeout treated as failure instead of unknown;
- missing idempotency/reconciliation;
- lock/sequence bypass;
- race/TOCTOU;
- wrong-target operation.

### Execution and sandbox

- arbitrary command/code execution;
- unsafe environment inheritance;
- privilege escalation;
- sandbox escape or misleading sandbox assumptions;
- executable/script provenance failure;
- writable/executable path abuse.

### Network and service trust

- unrestricted egress;
- access to localhost/private/metadata endpoints;
- server impersonation;
- excessive OAuth/token scope;
- insecure MCP/tool server;
- rate/cost/resource abuse;
- compromised external service response.

### Supply chain and release

- dependency confusion/substitution;
- compromised package/image/plugin/update;
- unpinned or unverifiable artifacts;
- malicious install/build scripts;
- provenance/SBOM gaps;
- signing/digest mismatch;
- release asset/source mismatch.

### Audit and recovery

- log/PII/secret leakage;
- mutable or incomplete audit trail;
- inability to reconstruct effects;
- ineffective backup/restore;
- incident containment gaps;
- security control silently disabled in production.

## Abuse-case questions

For each sensitive operation ask:

1. Can an unauthorized actor reach it?
2. Can the target, tenant, recipient, scope, or payload be swapped after authorization?
3. Can untrusted content influence instructions or tool parameters?
4. Can the same operation happen twice?
5. What happens on timeout or partial failure?
6. Can sensitive output escape through logs, errors, files, or model context?
7. Can a dependency/tool/service widen authority?
8. What evidence proves what actually happened?
9. What fails closed if a control or dependency is unavailable?
10. How is the operation contained or rolled back during an incident?
