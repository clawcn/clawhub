---
summary: "Concrete implementation plan for fixing ClawHub security scanner false positives, moderator overrides, malware gaps, appeals, and downstream removal propagation"
owner: "openclaw"
status: "draft"
last_updated: "2026-03-09"
title: "ClawHub Security Scanner Remediation Plan"
---

# ClawHub Security Scanner Remediation Plan

This is the working implementation plan for fixing ClawHub's current security scanner false
positives, malware detection gaps, appeal workflow, and downstream removal propagation.

Canonical umbrella issues:

- [#181](https://github.com/openclaw/clawhub/issues/181) verdict model, tiered labels, and scan UX
- [#211](https://github.com/openclaw/clawhub/issues/211) security tools flagged as suspicious
- [#91](https://github.com/openclaw/clawhub/issues/91) social engineering malware in skills
- [#129](https://github.com/openclaw/clawhub/issues/129) malicious skill persistence in downstream archives/mirrors
- [#371](https://github.com/openclaw/clawhub/issues/371) appeal workflow
- [#288](https://github.com/openclaw/clawhub/issues/288) behavioral security signal
- [#192](https://github.com/openclaw/clawhub/issues/192) verified publisher context

## Goals

- Reduce false-positive scanner issues by at least 80%.
- Stop treating a lone VT Code Insight concern as a platform-wide suspicious verdict.
- Give moderators an immediate way to unflag false positives so the existing ad-hoc appeal queue
  can start closing before the full review workflow ships.
- Catch the social-engineering and runtime-payload patterns reported in
  [#91](https://github.com/openclaw/clawhub/issues/91),
  [#571](https://github.com/openclaw/clawhub/issues/571), and
  [#627](https://github.com/openclaw/clawhub/issues/627) at publish time.
- Give authors a structured appeal path instead of forcing public GitHub issue spam.
- Ensure removed malicious skills are no longer installable from downstream mirrors or archive
  repos.

## Non-goals

- Perfect malware detection.
- Fully replacing manual moderation.
- Using publisher reputation as a hard security bypass.
- Shipping a first version that requires a third-party behavioral scan provider.

## Confirmed Root Causes

- `convex/vt.ts` prioritizes VT `code_insight` over engine detections when both exist.
- `convex/lib/moderationReasonCodes.ts` only supports `clean | suspicious | malicious`.
- `convex/lib/moderationReasonCodes.ts` returns `suspicious` for any non-malicious reason code.
- `convex/lib/moderationEngine.ts` adds VT and LLM scanner results directly into the final reason
  code set, so one noisy signal poisons the aggregate verdict.
- `convex/lib/moderationEngine.ts` only scans markdown for prompt-injection phrasing; it does not
  scan `SKILL.md` for social-engineering installers, base64 shell, fake prerequisites, or runtime
  payload patterns.
- `packages/clawdhub/src/cli/commands/skills.ts` requires `--force` for any suspicious skill in
  non-interactive installs and updates.
- Moderators do not have a lightweight product path to clear a known false positive and close the
  corresponding ad-hoc appeal.
- `src/components/SkillHeader.tsx` points authors at a generic GitHub issue flow instead of a
  structured review queue.

## Issue-Derived False-Positive Taxonomy

Live open issues show that the false positives are not random. The current appeal queue clusters
into a few repeatable buckets that should drive prioritization.

Highest-volume buckets:

- stale suspicious state after rescans or version updates
  - representative issues:
    [#733](https://github.com/openclaw/clawhub/issues/733),
    [#728](https://github.com/openclaw/clawhub/issues/728),
    [#669](https://github.com/openclaw/clawhub/issues/669),
    [#656](https://github.com/openclaw/clawhub/issues/656),
    [#655](https://github.com/openclaw/clawhub/issues/655),
    [#782](https://github.com/openclaw/clawhub/issues/782)
- API-wrapper and MCP-server patterns treated as suspicious because they combine env vars and
  documented network calls
  - representative issues:
    [#813](https://github.com/openclaw/clawhub/issues/813),
    [#803](https://github.com/openclaw/clawhub/issues/803),
    [#791](https://github.com/openclaw/clawhub/issues/791),
    [#790](https://github.com/openclaw/clawhub/issues/790),
    [#789](https://github.com/openclaw/clawhub/issues/789),
    [#788](https://github.com/openclaw/clawhub/issues/788)
- docs-only or markdown-only skills flagged because they mention API keys, install commands, or
  external URLs
  - representative issues:
    [#808](https://github.com/openclaw/clawhub/issues/808),
    [#782](https://github.com/openclaw/clawhub/issues/782),
    [#781](https://github.com/openclaw/clawhub/issues/781)
- shell, `child_process`, `subprocess`, or `sys.path` usage treated as suspicious even when the
  invocation is constrained, local, and expected
  - representative issues:
    [#799](https://github.com/openclaw/clawhub/issues/799),
    [#650](https://github.com/openclaw/clawhub/issues/650),
    [#317](https://github.com/openclaw/clawhub/issues/317),
    [#798](https://github.com/openclaw/clawhub/issues/798)
- security and defensive tools flagged because they contain attack signatures, test fixtures, or
  prompt-injection examples
  - representative issues:
    [#718](https://github.com/openclaw/clawhub/issues/718),
    [#699](https://github.com/openclaw/clawhub/issues/699),
    [#211](https://github.com/openclaw/clawhub/issues/211)
- metadata completeness and declaration problems escalated as security findings
  - representative issues:
    [#803](https://github.com/openclaw/clawhub/issues/803),
    [#663](https://github.com/openclaw/clawhub/issues/663)
- scanner output is too opaque for authors to remediate quickly
  - representative issue:
    [#731](https://github.com/openclaw/clawhub/issues/731)

Implications for prioritization:

- The highest-yield wins are stale-flag clearing, docs-only fast paths, MCP/API-wrapper semantics,
  and metadata-warning downgrades.
- We should not trade those wins against real malware detection in markdown/install flows. The
  false-positive work must ship alongside stronger social-engineering detection, not instead of it.

## Delivery Plan

## Phase 1: Moderator Override and Unflagging Tools

Primary issues:

- [#371](https://github.com/openclaw/clawhub/issues/371)
- [#181](https://github.com/openclaw/clawhub/issues/181)

Objective:

- Let moderators clear known false positives immediately so ad-hoc appeal issues can be resolved
  before the deeper scanner fixes land.

Data model:

- Add a `manualOverride` field on skills with:
  - `verdict`
  - `note`
  - `reviewerUserId`
  - `updatedAt`

Product flow:

- Add staff-only moderation actions to unflag a skill from `suspicious` to `clean`.
- Require an audit note and store the reviewer identity on every override.
- Continue using existing GitHub issues as the intake path for now, but resolve them through the
  moderation tool instead of manual data edits.

Implementation files in ClawHub:

- `convex/schema.ts`
- moderation mutations/queries in `convex/skills.ts` or a dedicated moderation module
- staff moderation UI/routes

Acceptance criteria:

- Moderators can unflag a suspicious skill without database edits.
- Existing ad-hoc false-positive appeals can be closed once an override is applied and recorded.
- Overrides are auditable and can be cleared manually when moderators want scanner-derived state to
  take over again.

Implementation phase:

- Schema
  - Add an optional `manualOverride` object on `skills`.
  - Store `verdict`, `note`, `reviewerUserId`, and `updatedAt`.
- Backend API
  - Add a staff-only mutation to apply a skill-level override and a companion mutation to clear it.
  - Reuse `auditLogs` for override/unflag events instead of adding a new audit sink.
  - Require a non-empty audit note on every override/clear mutation.
  - Preserve raw scanner evidence/reason codes on the skill while changing the effective aggregate
    verdict, status flags, and summary to the manual override state.
- Effective state rules
  - `clean` overrides clear the legacy `flagged.suspicious` state and keep the skill public.
  - New publishes and rescans continue updating scanner evidence underneath, but the active
    skill-level override still controls the live/public moderation state until a moderator clears
    it.
- UI
  - Extend the staff management console with an override panel on the existing skill tooling
    surface.
  - Support applying a `clean` override, entering a required audit note, and clearing the current
    override from the same panel.
  - Show the current skill-level override and latest version context so moderators can confirm what
    is in effect before applying a new action.
  - Add direct `Manage` entry points from reported skills and recent pushes into the existing
    management flow.
- Migration/backfill
  - No backfill is required because the new fields are optional and Phase 1 only affects new staff
    actions.
  - Generated Convex types need regeneration after schema updates.

Validation methods:

- Backend unit tests
  - mutation tests for skill-level override application and audit log insertion
  - mutation tests for manual clear restoring scanner-derived moderation state
  - regression tests that skill-level overrides continue to win when new scanner data is written
- Frontend validation
  - manual verification in the management console that moderators can apply a `clean` override with
    a required note
  - manual verification that recent-push entry points open the correct skill in management
  - manual verification that the flagged warning disappears from the skill page once the skill
    override is applied
- Local Convex validation
  - run against the local Convex deployment only
  - push functions locally before `convex run`
  - seed or select an already suspicious local skill, apply an override, and confirm audit log +
    visible moderation state changes without any manual DB edits
  - clear the override and confirm the skill falls back to the scanner-derived state

## Phase 2: Signal Model and Verdict Arbitration

Detailed implementation spec:

- [`docs/plans/signal-model-verdict-arbitration-implementation-plan.md`](./signal-model-verdict-arbitration-implementation-plan.md)

Primary issues:

- [#181](https://github.com/openclaw/clawhub/issues/181)
- [#192](https://github.com/openclaw/clawhub/issues/192)

Objective:

- Stop early collapsing of scanner signals.
- Introduce clearer signal arbitration while keeping aggregate verdicts to `clean`, `suspicious`,
  and `malicious`.
- Reduce the largest repeat false-positive buckets without allowing a single noisy scanner or
  metadata mismatch to poison the aggregate verdict.

Schema changes in ClawHub:

- Update `convex/schema.ts` to keep the aggregate verdict enum explicit as `clean`, `suspicious`,
  and `malicious`.
- Add a structured `moderationSignals` object on skills and versions with:
  - `staticScan`
  - `vtEngines`
  - `vtCodeInsight`
  - `llmScan`
  - `behavioralScan`
  - `publisherTrust`
  - `manualOverride`
- Keep existing legacy flags for compatibility during rollout.

Shared API/schema changes:

- Update `packages/schema/src/schemas.ts`.
- Update `packages/clawdhub/src/schema/schemas.ts`.
- Expose both the aggregate verdict and per-signal verdicts in API responses.

Operational changes:

- Add a bulk backfill/rescan path so the new verdict arbitration can be applied to all existing
  skills before issue cleanup begins.

Decision rules:

- `malicious`
  - known blocked signatures
  - explicit exfiltration
  - obfuscated remote code execution
  - manual moderator override
  - high-confidence behavioral malicious signal when that signal exists
- `suspicious`
  - two independent medium-or-higher risk signals
  - undeclared dangerous behavior plus scanner concern
  - explicit capability mismatch between declared behavior and observed behavior
- `clean`
  - no meaningful risk signals
  - informational findings and metadata mismatches may still be present

Hard rules:

- VT Code Insight alone cannot produce aggregate `suspicious`.
- Publisher trust can reduce false-positive pressure but can never downgrade `suspicious` or
  `malicious`.
- Existing `flagged.suspicious` compatibility should only map from aggregate `suspicious`.

Additional arbitration rules:

- Metadata and declaration mismatches are tracked separately from security verdicts.
  - Missing env declarations, undeclared hooks, install-method mismatch, or capability drift should
    produce metadata findings, not `suspicious`, unless paired with an independent security signal.
- Docs-only fast path.
  - If the bundle contains only markdown/text files and no executable content, documentation text
    alone cannot produce aggregate `suspicious` unless it contains explicit social-engineering or
    malware-install patterns from Phase 5.
- API-wrapper / MCP fast path.
  - `env + network` is not suspicious by itself when the observed behavior matches the declared
    capability, targets an official vendor domain or localhost, and does not include unrelated
    exfiltration or obfuscation signals.
- Fixed-binary exec fast path.
  - `spawn` / `subprocess` / local CLI invocation is not suspicious by itself when it is non-shell,
    calls a fixed binary, and arguments are constrained to the skill's declared capability.
- Security-tool carveout.
  - Malware signatures, prompt-injection examples, and attack strings inside security tooling or
    defensive test fixtures do not become `malicious` or `suspicious` unless paired with an actual
    execution, delivery, or exfiltration path.
- Stale-state reset.
  - If current VT and OpenClaw/LLM signals are clean and the only remaining suspicious driver is an
    older scanner result, the aggregate suspicious flag must clear automatically on rescan.

Implementation files in ClawHub:

- `convex/vt.ts`
- `convex/lib/moderationEngine.ts`
- `convex/lib/moderationReasonCodes.ts`
- `convex/skills.ts`
- `convex/httpApiV1/skillsV1.ts`
- `packages/schema/src/schemas.ts`
- `packages/clawdhub/src/schema/schemas.ts`

Acceptance criteria:

- Cases like [#387](https://github.com/openclaw/clawhub/issues/387),
  [#448](https://github.com/openclaw/clawhub/issues/448),
  [#450](https://github.com/openclaw/clawhub/issues/450),
  [#656](https://github.com/openclaw/clawhub/issues/656), and
  [#658](https://github.com/openclaw/clawhub/issues/658) no longer become aggregate
  `suspicious` when VT engines are clean and OpenClaw/local scan is benign.
- Existing clients that only understand `isSuspicious` continue to work during migration.
- A full rescan can be run across existing skills using the new arbitration rules.
- Representative issues in the main false-positive buckets move to `clean` under the new
  arbitration rules:
  - docs-only: [#808](https://github.com/openclaw/clawhub/issues/808)
  - stale VT/OpenClaw disagreement:
    [#733](https://github.com/openclaw/clawhub/issues/733)
  - API-wrapper / env + network:
    [#813](https://github.com/openclaw/clawhub/issues/813)
  - constrained `child_process`:
    [#799](https://github.com/openclaw/clawhub/issues/799)
  - security-tool signatures:
    [#699](https://github.com/openclaw/clawhub/issues/699)

## Phase 3: Rescan and Issue Cleanup

Objective:

- Re-run moderation on the full existing corpus with the new verdict model, then close resolved
  scanner issues against the updated results.
- Explicitly verify that stale suspicion is recomputed from the current version state rather than
  inherited from previous versions or cached VT Code Insight outcomes.

Tasks:

- Run the Phase 2 backfill/rescan path across all existing skills and versions.
- Add a targeted stale-flag cleanup pass before the full corpus rescan.
  - detect skills where the live aggregate state is `suspicious` or `malicious` but current VT and
    OpenClaw/LLM signals are clean
  - recompute moderation from current evidence only
  - emit metrics for how many skills were cleared by stale-state repair vs new arbitration
- Keep umbrella issues open:
  [#181](https://github.com/openclaw/clawhub/issues/181),
  [#211](https://github.com/openclaw/clawhub/issues/211),
  [#91](https://github.com/openclaw/clawhub/issues/91),
  [#129](https://github.com/openclaw/clawhub/issues/129),
  [#371](https://github.com/openclaw/clawhub/issues/371),
  [#288](https://github.com/openclaw/clawhub/issues/288), and
  [#192](https://github.com/openclaw/clawhub/issues/192).
- Close resolved false-positive tickets after rescan confirms the skill is now `clean`.
- Close remaining generic false-positive tickets as duplicates of
  [#181](https://github.com/openclaw/clawhub/issues/181) unless they introduce a new trigger
  pattern.
- Close remaining security-tool false-positive tickets as duplicates of
  [#211](https://github.com/openclaw/clawhub/issues/211).
- Keep malware campaign reports open until takedown and user-safety actions are verified, but link
  them to [#91](https://github.com/openclaw/clawhub/issues/91).
- Keep downstream persistence reports linked to
  [#129](https://github.com/openclaw/clawhub/issues/129).

Deliverable:

- Backlog updated after the rescan, with resolved false positives closed and the remaining open
  issues concentrated into the canonical umbrella threads or true unresolved cases.

## Phase 4: UI and CLI Policy Update

Primary issues:

- [#181](https://github.com/openclaw/clawhub/issues/181)
- [#211](https://github.com/openclaw/clawhub/issues/211)

Objective:

- Make `suspicious` and `malicious` materially different in product behavior while keeping
  everything else `clean`.

UI changes in ClawHub:

- Update `src/components/SkillSecurityScanResults.tsx` to show per-signal rows, not one blended
  status.
- Update `src/components/SkillHeader.tsx` banner language:
  - `suspicious`: "conflicting or risky behavior detected, review carefully"
  - `malicious`: blocked
- Add explicit evidence and reason code display.
- Split "security findings" from "metadata/compliance findings" in owner-facing views.
- Show why a docs-only or security-tool carveout applied when that context is what kept the skill
  `clean`.
- Add docs-only and security-tool context copy where applicable.

CLI changes in ClawHub:

- Update `packages/clawdhub/src/cli/commands/skills.ts`.
- `malicious`: block install and update.
- `suspicious`: prompt in interactive mode, require `--force` in non-interactive mode.

Acceptance criteria:

- Security-tool and docs-only skills can remain installable when they stay `clean`.
- Truly suspicious skills still require a deliberate override.
- Authors can see rule id, severity, file, line, evidence snippet, and remediation hint for each
  scanner finding without opening GitHub issues.

## Phase 5: Social Engineering and Runtime-Payload Scanner

Primary issues:

- [#91](https://github.com/openclaw/clawhub/issues/91)
- [#571](https://github.com/openclaw/clawhub/issues/571)
- [#627](https://github.com/openclaw/clawhub/issues/627)

Objective:

- Catch the attack class that currently lives in `SKILL.md` and install instructions.

Scanner changes:

- Expand markdown scanning in `convex/lib/moderationEngine.ts` to inspect:
  - code fences
  - inline shell commands
  - prerequisite/install sections
  - frontmatter install metadata
- Add signatures for:
  - `curl | bash`, `wget | sh`, PowerShell `iex`
  - base64 decode plus execution
  - password-protected archive download instructions
  - raw IP or paste-site installers
  - fake prerequisite binaries
  - repeated urgency language as supporting evidence
  - external executable download outside the bundle

Severity matrix:

- raw IP or paste-site remote payload plus execution: `malicious`
- password-protected archive plus execution instructions: `malicious`
- external installer without checksum or declared vendor domain: `suspicious`
- external prerequisite with declared vendor domain and checksum: supporting evidence only
- urgency language by itself: supporting evidence only

Data model changes:

- Add new reason codes for markdown/runtime-install attack patterns in
  `convex/lib/moderationReasonCodes.ts`.

Operational changes:

- Add backfill/rescan path so new signatures can be applied across existing skills.
- Auto-hide or block on high-confidence malicious markdown patterns.

Acceptance criteria:

- The patterns described in [#91](https://github.com/openclaw/clawhub/issues/91),
  [#571](https://github.com/openclaw/clawhub/issues/571), and
  [#627](https://github.com/openclaw/clawhub/issues/627) are caught before public listing.

## Phase 6: Security Tool Profile and Docs-Only Fast Path

Primary issues:

- [#211](https://github.com/openclaw/clawhub/issues/211)
- [#386](https://github.com/openclaw/clawhub/issues/386)
- [#598](https://github.com/openclaw/clawhub/issues/598)

Objective:

- Stop penalizing security infrastructure and docs-only skills for containing legitimate
  high-risk-looking content.

Manifest and metadata changes:

- Add optional fields:
  - `skillCategory`: `security_tool | integration | automation | docs_only | general`
  - `declaredCapabilities`
  - `declaredNetworkDestinations`
  - `declaredWrites`
- Treat them as hints for consistency checking, not as trusted bypasses.

Scanner behavior:

- If `skillCategory = security_tool`, test fixtures and signature databases should not escalate by
  themselves.
- If `skillCategory = docs_only` and bundle has no executable files, lone documentation references
  should not produce aggregate `suspicious` without corroborating signals.
- If declared capabilities match observed risky behavior, avoid escalating on that signal alone.
- If undeclared risky behavior is observed, escalate.
- If behavior is declared but the declaration is incomplete or malformed, surface a metadata finding
  first and only escalate when an independent security signal is present.
- For localhost-only and vendor-domain-only integrations, treat documented destinations as
  supporting context rather than a suspicion trigger.

Implementation files in ClawHub:

- `convex/lib/moderationEngine.ts`
- `convex/lib/moderationReasonCodes.ts`
- upload/publish metadata parsing paths
- `packages/schema/src/schemas.ts`
- `packages/clawdhub/src/schema/schemas.ts`

Acceptance criteria:

- Issues like [#211](https://github.com/openclaw/clawhub/issues/211),
  [#386](https://github.com/openclaw/clawhub/issues/386), and
  [#598](https://github.com/openclaw/clawhub/issues/598) move from `suspicious` to `clean` when
  their behavior is declared and consistent.
- Representative open buckets also clear under this phase when their behavior is declared and
  bounded:
  - docs-only:
    [#808](https://github.com/openclaw/clawhub/issues/808)
  - localhost/local-only tools:
    [#420](https://github.com/openclaw/clawhub/issues/420),
    [#816](https://github.com/openclaw/clawhub/issues/816)
  - API wrappers and MCP servers:
    [#813](https://github.com/openclaw/clawhub/issues/813),
    [#791](https://github.com/openclaw/clawhub/issues/791),
    [#790](https://github.com/openclaw/clawhub/issues/790)
  - constrained local exec:
    [#799](https://github.com/openclaw/clawhub/issues/799),
    [#317](https://github.com/openclaw/clawhub/issues/317)
  - security tooling with signatures:
    [#699](https://github.com/openclaw/clawhub/issues/699),
    [#718](https://github.com/openclaw/clawhub/issues/718)

## Phase 7: Structured Appeal Workflow

Primary issues:

- [#371](https://github.com/openclaw/clawhub/issues/371)

Objective:

- Replace generic GitHub issue filing with a structured review flow.

Data model:

- Add `skillModerationAppeals` table with:
  - `skillId`
  - `versionId`
  - `ownerUserId`
  - `aggregateVerdict`
  - `signalSnapshot`
  - `reasonCodes`
  - `evidence`
  - `authorStatement`
  - `status`
  - `reviewerUserId`
  - `reviewNotes`
  - `createdAt`
  - `updatedAt`

Product flow:

- Add owner-only `Request review` action on flagged skill pages.
- Pre-fill slug, version, verdicts, reasons, VT URL, repo URL, and author explanation.
- Add moderator queue and review actions in staff tooling on top of the override capability from
  Phase 1.
- Keep GitHub issues for new scanner classes only, not routine appeals.

Implementation files in ClawHub:

- `convex/schema.ts`
- moderation mutations/queries in `convex/skills.ts` or a dedicated moderation module
- `src/components/SkillHeader.tsx`
- new appeal dialog and staff queue UI

Acceptance criteria:

- False-positive appeals no longer require public issue creation.
- Authors can submit structured review requests without opening a GitHub issue.

## Phase 8: Downstream Removal Propagation

Primary issues:

- [#129](https://github.com/openclaw/clawhub/issues/129)

Objective:

- Make removed malicious skills disappear everywhere, not just on the main site.

Registry/state changes:

- Publish a canonical registry state feed that includes:
  - active versions
  - removed versions
  - moderation status
  - tombstones
- Update the archive sync so removed or malicious skills are tombstoned, not left as public active
  files.
- Add drift detection between ClawHub DB state and archive/mirror state.

Cross-repo dependency:

- This phase likely requires coordinated changes in the downstream archive repo and mirror tooling,
  not just `openclaw/clawhub`.

Acceptance criteria:

- A removed malicious skill is hidden and install-blocked from the main site and downstream mirrors
  within minutes.

## Phase 9: Behavioral Security Signal

Primary issues:

- [#288](https://github.com/openclaw/clawhub/issues/288)

Objective:

- Add a third signal that evaluates runtime behavior instead of bundle-at-rest heuristics only.

Spec:

- Add a provider abstraction for asynchronous behavioral scan results.
- Store per-skill behavioral verdict, score, summary, and checked timestamp.
- Surface behavioral results alongside VT and OpenClaw scan results.
- Initially treat behavioral scans as additive and non-blocking unless they produce a very strong
  malicious signal.

Implementation files in ClawHub:

- scanner integration module
- `convex/schema.ts`
- `convex/skills.ts`
- API response schemas
- `src/components/SkillSecurityScanResults.tsx`

Acceptance criteria:

- Behavioral scan results can be displayed and included in aggregate arbitration without replacing
  existing scanners.

## Recommended Rollout Order

1. Phase 1 moderator override and unflagging tools.
2. Phase 2 signal model and verdict arbitration.
3. Phase 3 rescan and stale-flag cleanup.
4. Phase 4 UI and CLI policy update.
5. Phase 6 security-tool profile and docs-only fast path.
6. Phase 5 social-engineering and runtime-payload scanning.
7. Phase 7 structured appeals workflow.
8. Phase 8 downstream removal propagation.
9. Phase 9 behavioral signal integration.

Rationale:

- The issue backlog indicates stale-state repair plus better arbitration will close the biggest
  false-positive bucket fastest.
- Docs-only, API-wrapper, MCP, and security-tool carveouts should land before or alongside the next
  large rescan so we do not re-flag the same classes.
- Phase 5 remains critical for false negatives and should still ship early, but not at the cost of
  delaying the highest-volume false-positive fixes.

## Test Plan

ClawHub test coverage to add:

- moderator override mutation tests, including audit note and clear-override behavior
- unit tests for aggregate verdict arbitration
- stale-state recomputation tests where current VT/OpenClaw signals are clean but legacy aggregate
  state remains suspicious
- bulk rescan/backfill tests for re-evaluating existing skills under the new verdict model
- regression tests for VT engines clean plus Code Insight suspicious
- regression tests for benign VT/OpenClaw plus old suspicious state inherited from previous
  versions
- markdown scanner tests for:
  - `curl | bash`
  - base64 shell payloads
  - password-protected archive instructions
  - raw IP and paste-site payloads
  - fake prerequisite copy
- docs-only skill classification tests
- docs-only skill tests with API key placeholders, install examples, and external links
- security-tool fixture tests
- API-wrapper tests with declared vendor domains and env-key usage
- MCP/server tests with localhost or documented SSE/HTTP transport
- constrained `child_process` / `subprocess` tests for fixed-binary non-shell execution
- metadata mismatch tests that stay non-security unless paired with a second risk signal
- API snapshot tests for per-signal output
- CLI tests for `suspicious` vs `malicious` policy differences
- downstream sync tests for tombstone propagation
- golden corpus tests:
  - a representative false-positive set drawn from open issues
  - a representative malicious set drawn from confirmed malware reports
  - block rollout if false positives do not fall substantially or any known-malicious sample turns
    `clean`

## Success Metrics

- false-positive issue creation rate drops by at least 80%
- open false-positive appeal backlog in the main buckets drops by at least 60% after the first
  full rescan
- malware reports of the [#91](https://github.com/openclaw/clawhub/issues/91) class are caught
  pre-publish
- median appeal resolution time is under 2 business days
- removed malicious skills are no longer visible in downstream mirrors after propagation
- zero regressions on the confirmed-malicious validation corpus used for rollout

## Open Questions

- How much publisher trust should be allowed to influence aggregate verdicts, if at all?
- Should manual overrides remain moderator-only indefinitely, or should later phases add a second
  review/escalation workflow for high-risk overrides?
