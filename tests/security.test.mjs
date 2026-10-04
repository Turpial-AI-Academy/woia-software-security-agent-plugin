import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");

const skillRoot = path.join(ROOT, "skills", "security");

test("security review is bound to an exact candidate and treats QA as input", async () => {
  const skill = await readFile(path.join(skillRoot, "SKILL.md"), "utf8");
  assert.match(skill, /Bind the review to an exact candidate identity/i);
  assert.match(skill, /Treat prior QA as an input, not as proof of security/i);
  assert.match(skill, /commit\/tree\/artifact\/version identity/i);
  assert.match(skill, /changed candidate invalidates evidence or acceptance/i);
});

test("security method covers authority, untrusted input, effects, observability and supply chain", async () => {
  const method = await readFile(path.join(skillRoot, "references", "SECURITY_REVIEW_METHOD.md"), "utf8");
  for (const phrase of [
    "Secrets and authority",
    "Authentication, authorization, tenancy, approvals",
    "Untrusted input and injection",
    "External effects and state",
    "Observability and audit",
    "Supply chain",
    "Operations and recovery",
  ]) assert.ok(method.toLowerCase().includes(phrase.toLowerCase()), phrase);
  assert.match(method, /timeout may mean `unknown`, not `failed`/i);
});

test("threat model includes agentic, filesystem, network and release attack families", async () => {
  const threat = await readFile(path.join(skillRoot, "references", "THREAT_MODEL.md"), "utf8");
  for (const phrase of [
    "prompt injection",
    "path traversal/symlink escape",
    "SSRF",
    "confused deputy",
    "duplicate effects",
    "dependency confusion/substitution",
    "mutable or incomplete audit trail",
  ]) assert.ok(threat.toLowerCase().includes(phrase.toLowerCase()), phrase);
});

test("finding policy separates severity from release blocking status", async () => {
  const policy = await readFile(path.join(skillRoot, "references", "FINDINGS_AND_RISK_ACCEPTANCE.md"), "utf8");
  assert.match(policy, /A finding is blocking when/i);
  for (const phrase of ["P0 - Critical", "P1 - High", "P2 - Medium", "P3 - Low"]) assert.ok(policy.includes(phrase), phrase);
  assert.match(policy, /`DEFERRED` is not equivalent to `ACCEPTED`/);
  assert.match(policy, /Aggregate risk/);
});

test("risk acceptance requires explicit authority, scope, candidate binding and review conditions", async () => {
  const policy = await readFile(path.join(skillRoot, "references", "FINDINGS_AND_RISK_ACCEPTANCE.md"), "utf8");
  const template = await readFile(path.join(skillRoot, "assets", "risk-acceptance.template.md"), "utf8");
  assert.match(policy, /accountable human\/role must authorize/i);
  for (const phrase of ["Finding ID", "Commit/tree/artifact identity", "Role / authority", "Rationale", "Expires on / review by", "Re-review triggers"]) {
    assert.ok(template.toLowerCase().includes(phrase.toLowerCase()), phrase);
  }
  assert.match(template, /candidate changes affecting this risk/i);
});

test("validation playbook never turns unavailable checks into pass evidence", async () => {
  const playbook = await readFile(path.join(skillRoot, "references", "VALIDATION_PLAYBOOK.md"), "utf8");
  assert.match(playbook, /do not label it PASS/i);
  assert.match(playbook, /scanner or environment is unavailable/i);
  assert.match(playbook, /tool severity directly into release severity/i);
  assert.match(playbook, /Remediation verification/);
});

test("security evidence template captures candidate, findings, acceptance and tri-state gate", async () => {
  const report = await readFile(path.join(skillRoot, "assets", "security-evidence.template.md"), "utf8");
  for (const phrase of [
    "Commit SHA",
    "Tree SHA",
    "QA approval reference",
    "Evidence executed",
    "Findings",
    "Accepted residual risks",
    "Skipped or blocked checks",
    "`PASS`",
    "`BLOCKED`",
    "`INCOMPLETE`",
  ]) assert.ok(report.toLowerCase().includes(phrase.toLowerCase()), phrase);
});

test("skill pass semantics match the security contract boundary", async () => {
  const skill = await readFile(path.join(skillRoot, "SKILL.md"), "utf8");
  assert.match(skill, /no unresolved blocking security risks for the reviewed candidate/i);
  assert.match(skill, /every blocking residual risk has a valid explicit acceptance/i);
  assert.match(skill, /`PASS`, `BLOCKED`, or `INCOMPLETE`/);
  assert.match(skill, /does not mean the system is vulnerability-free/i);
});

test("bounded security follow-up preserves the candidate, controls, findings and acceptance", async () => {
  const skill = await readFile(path.join(skillRoot, "SKILL.md"), "utf8");
  for (const obligation of [
    /bounded[\s\S]*(healthy|valid)[\s\S]*(review|threat map)[\s\S]*(same|unchanged) exact candidate/i,
    /metadata[\s\S]*documentation[\s\S]*outside[\s\S]*production candidate/i,
    /candidate bytes[\s\S]*attack surfaces[\s\S]*controls[\s\S]*finding dispositions[\s\S]*risk acceptances[\s\S]*unchanged/i,
    /(smallest|targeted)[\s\S]*unit[\s\S]*preserv\w*[\s\S]*(unrelated|unaffected)[\s\S]*records/i,
    /re-check[\s\S]*candidate[\s\S]*scope coverage[\s\S]*blocking findings[\s\S]*authority[\s\S]*conditions[\s\S]*validity/i,
  ]) assert.match(skill, obligation);
});

test("deep security review is triggered by material boundaries and evidence drift", async () => {
  const skill = await readFile(path.join(skillRoot, "SKILL.md"), "utf8");
  const triggers = skill.split(/\r?\n\r?\n/).find((paragraph) => /deep path/i.test(paragraph) && /new review/i.test(paragraph)) ?? "";
  for (const trigger of [
    /new review[\s\S]*candidate/i,
    /API[\s\S]*event[\s\S]*schema/i,
    /persisted[\s\S]*migrations/i,
    /authentication[\s\S]*authorization[\s\S]*secrets[\s\S]*signing[\s\S]*trust/i,
    /supply-chain/i,
    /deployment[\s\S]*recovery/i,
    /provider[\s\S]*dependencies/i,
    /expired[\s\S]*acceptance[\s\S]*advisories/i,
    /contradict\w*[\s\S]*evidence[\s\S]*missing[\s\S]*durable[\s\S]*proof/i,
  ]) assert.match(triggers, trigger);
});

test("security reuse independently inspects durable proof and invalidates affected risks only", async () => {
  const skill = await readFile(path.join(skillRoot, "SKILL.md"), "utf8");
  const method = await readFile(path.join(skillRoot, "references", "SECURITY_REVIEW_METHOD.md"), "utf8");
  for (const obligation of [
    /independent\w*[\s\S]*(owns|ownership)[\s\S]*gate/i,
    /durable evidence[\s\S]*actual execution[\s\S]*candidate[\s\S]*environment[\s\S]*scope[\s\S]*provenance[\s\S]*freshness/i,
    /summaries[\s\S]*recollection[\s\S]*assumptions[\s\S]*do not prove security/i,
    /execute[\s\S]*relevant checks[\s\S]*proof[\s\S]*independent\w*[\s\S]*BLOCKED[\s\S]*INCOMPLETE/i,
    /reusable evidence[\s\S]*invalidated evidence[\s\S]*fresh execution[\s\S]*assumptions/i,
    /invalidate only[\s\S]*affected[\s\S]*change/i,
    /load[\s\S]*when[\s\S]*existing[\s\S]*report/i,
  ]) assert.match(skill, obligation);
  assert.match(method, /advisory changes[\s\S]*expired acceptance[\s\S]*control drift[\s\S]*invalidate[\s\S]*without[\s\S]*source mutation/i);
});
