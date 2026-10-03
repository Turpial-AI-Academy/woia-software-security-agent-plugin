# Findings and Risk Acceptance

## Finding model

Every material finding should contain:

- stable ID;
- title;
- severity `P0`, `P1`, `P2`, or `P3`;
- status;
- exact candidate/surface;
- evidence location or reproduction;
- preconditions/attacker model;
- scenario;
- impact;
- affected security property;
- remediation;
- verification/regression plan;
- blocking rationale;
- residual uncertainty.

Recommended statuses:

~~~text
OPEN
REMEDIATED
ACCEPTED
FALSE_POSITIVE
DEFERRED
~~~

`DEFERRED` is not equivalent to `ACCEPTED`.

## Severity guidance

Severity is context-dependent. Use impact, exploitability/preconditions, affected data/effects, scope, reversibility, external exposure, regulatory/contractual impact, uncertainty, recurrence, and detectability.

### P0 - Critical

Credible path to catastrophic or broad compromise, irreversible high-impact unauthorized effects, severe secret/data compromise, or equivalent release-stopping exposure.

Default: blocking.

### P1 - High

Credible path to significant unauthorized access/effect, substantial sensitive-data exposure, major privilege/tenant boundary failure, serious supply-chain compromise, or equivalent.

Default: blocking unless an explicitly authorized policy allows acceptance and the acceptance is valid.

### P2 - Medium

Material but constrained security weakness with limited scope, stronger preconditions, effective compensating control, or lower impact.

May still block based on product policy, regulated data, exposure, or aggregate risk.

### P3 - Low

Low-impact hardening gap, defense-in-depth improvement, or minor information exposure without a credible material effect under current evidence.

Usually non-blocking, but record it.

## Blocking decision

A finding is blocking when release policy, risk appetite, contractual/regulatory obligations, or the actual threat/impact requires resolution before the candidate can proceed.

A review is `PASS` only when:

- no blocking finding is `OPEN` or merely `DEFERRED`;
- every blocking residual risk that remains is `ACCEPTED` through a valid explicit acceptance;
- acceptance conditions and compensating controls are verified on the reviewed candidate;
- no unresolved uncertainty itself constitutes a blocking risk.

## Valid risk acceptance

Security review can recommend acceptance, but the accountable human/role must authorize it.

A valid acceptance records at least:

- finding/risk ID;
- exact candidate or immutable scope it applies to;
- affected asset/data/effect;
- scenario and residual impact;
- rationale for accepting rather than remediating now;
- compensating controls and required conditions;
- accepting owner/role and evidence of authority;
- decision timestamp;
- expiry or review trigger;
- remediation/follow-up owner when applicable;
- explicit statement that the risk is accepted.

## Invalid acceptance examples

Do not treat these as valid:

- "known issue" with no accountable owner;
- issue moved to backlog;
- developer self-approval without delegated risk authority;
- blanket acceptance for future versions;
- acceptance that omits the affected scope/candidate;
- expired acceptance;
- acceptance whose required compensating control is absent;
- approval that was for a different payload/target;
- silence or lack of response.

## Candidate binding

If a new commit/build changes the vulnerable code, authorization path, dependency, configuration, deployment assumptions, compensating control, or attack surface, reassess the risk and acceptance.

A rebase that preserves the exact certified tree may retain evidence if candidate identity equivalence is explicitly demonstrated. Do not assume equivalence from branch names or intent.

## Aggregate risk

Several individually non-blocking findings can combine into a blocking chain. Consider attack composition, shared root causes, and defense dependencies before final gate status.
