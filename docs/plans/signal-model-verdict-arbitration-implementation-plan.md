---
summary: 'Detailed Phase 2 implementation spec for security signal normalization, verdict arbitration, API exposure, and rollout.'
read_when:
  - Implementing Phase 2 of the security scanner remediation plan
  - Changing moderation verdict logic
  - Splitting VT / LLM / static scan signals
---

# Signal Model and Verdict Arbitration Implementation Plan

This document turns Phase 2 of [`docs/plans/security-scanner-remediation-plan.md`](./security-scanner-remediation-plan.md) into an implementation spec tied to the current ClawHub codebase.

It is intentionally narrower than the umbrella plan:

- It covers signal normalization, verdict arbitration, schema/API changes, migration, and tests.
- It does not cover the moderator appeal workflow, downstream propagation, or the later behavioral scanner provider integration beyond reserving schema hooks.

## Scope

Goals:

- Keep the public aggregate verdict model explicit and stable: `clean | suspicious | malicious`.
- Stop collapsing all evidence into a flat reason-code bag where any non-malicious signal becomes `suspicious`.
- Split source signals so VT engines, VT Code Insight, static scan, and LLM evaluation can be reasoned about independently.
- Track metadata/compliance drift separately from security verdicts.
- Make stale-state clearing deterministic on recompute.
- Preserve all current compatibility fields used by browse/search/API clients during rollout.

Non-goals for this phase:

- No change to public visibility policy beyond the new aggregate verdict outcome.
- No new review UI beyond exposing the richer signal model through existing endpoints.
- No requirement that the behavioral scanner ship in the same PR; Phase 2 only reserves the shape.

## Current Problems in the Repo

Current code paths that need to change:

- `convex/lib/moderationEngine.ts`
  - `buildModerationSnapshot()` appends static reason codes plus VT/LLM status-derived codes into one flat list.
- `convex/lib/moderationReasonCodes.ts`
  - `verdictFromCodes()` returns `suspicious` for any non-empty non-malicious code set.
- `convex/skills.ts`
  - `buildScannerModerationPatchFromVersion()` and `approveSkillByHashInternal` still rebuild moderation from the flat code list.
  - `isPrivilegedOwnerForSuspiciousBypass()` strips suspicious outcomes for staff-owned skills, which is a policy bypass hidden inside the arbitration path.
- `convex/vt.ts`
  - `vtAnalysis` currently stores a single flattened VT result even though VT exposes two materially different sources: AV engine stats and Code Insight.
- `convex/httpApiV1/skillsV1.ts`
  - `version.security` exposes scanner details, but `moderation` cannot explain which signals contributed, which were suppressed, and why.

Behavioral problems created by the current design:

- A lone noisy signal poisons the aggregate verdict.
- VT Code Insight and VT engines are treated as interchangeable when they are not.
- Metadata drift and declaration mismatches have no first-class place to live, so they get treated like security findings.
- Current-state recompute is incomplete; stale suspicion is partially cleared in rescan code instead of being a property of the arbitration engine itself.
- Staff-owned skills get special treatment inside the engine instead of through explicit moderation controls.

## Target Architecture

The moderation pipeline should have three layers:

1. Raw source data
   - Existing version-level scanner payloads remain the raw inputs.
   - These stay close to the source system and may be larger or more vendor-specific.

2. Normalized signal snapshot
   - A compact, uniform signal model is built from raw inputs.
   - This is the object arbitration consumes.
   - This snapshot also records suppressed and metadata-only findings so UI and appeals can explain outcomes.

3. Effective aggregate moderation state
   - The skill-level aggregate verdict, summary, legacy flags, and compatibility booleans remain the fields that browse/search/public visibility depend on.
   - These are derived only from the normalized signal snapshot plus any manual override.

## Signal Model

### Signal keys

Phase 2 normalizes the following keys:

- `staticScan`
- `vtEngines`
- `vtCodeInsight`
- `llmScan`
- `behavioralScan`
- `publisherTrust`
- `manualOverride`

### Signal families

Signals also need a family so arbitration can count independent sources correctly:

- `local`
- `vt`
- `llm`
- `behavioral`
- `trust`
- `manual`

Important rule:

- `vtEngines` and `vtCodeInsight` share the same `vt` family and must never count as two independent suspicious signals.

### Signal state vs signal verdict

Use separate fields for transport state and verdict:

- `state`: `ready | pending | error | not_applicable`
- `verdict`: `clean | suspicious | malicious` when `state = ready`

This keeps pending/error transport status out of the aggregate security verdict.

### Finding classes

Every normalized finding must be classified as one of:

- `security`
- `metadata`
- `context`

Interpretation:

- `security`: can contribute to aggregate arbitration.
- `metadata`: should never contribute by itself; it is surfaced separately.
- `context`: explanatory or suppressing context, not a risk signal.

### Contribution states

Each signal needs an explicit contribution result after normalization:

- `decisive`
- `corroborating`
- `suppressed`
- `informational`
- `none`

Interpretation:

- `decisive`: strong enough to directly determine or upgrade the aggregate verdict.
- `corroborating`: counts toward the two-independent-signal rule.
- `suppressed`: real source output, but intentionally not counted because a carveout applied.
- `informational`: show to users/staff, but never count.
- `none`: absent or not usable.

## Schema Changes

## `convex/schema.ts`

Add shared validators for:

- `signalState`
- `signalVerdict`
- `signalFamily`
- `findingClass`
- `signalContribution`

Add a compact `moderationSignalSummary` object:

```ts
{
  key: 'staticScan' | 'vtEngines' | 'vtCodeInsight' | 'llmScan' | 'behavioralScan' | 'publisherTrust' | 'manualOverride'
  family: 'local' | 'vt' | 'llm' | 'behavioral' | 'trust' | 'manual'
  state: 'ready' | 'pending' | 'error' | 'not_applicable'
  verdict?: 'clean' | 'suspicious' | 'malicious'
  contribution: 'decisive' | 'corroborating' | 'suppressed' | 'informational' | 'none'
  reasonCodes: string[]
  metadataCodes?: string[]
  suppressedReasonCodes?: string[]
  summary?: string
  rationale?: string
  checkedAt?: number
  details?: any
}
```

Add `moderationSignals` to both `skills` and `skillVersions`.

Version-level requirements:

- Store the canonical normalized signals for that version.
- Keep full static scan evidence in `staticScan.findings`; do not duplicate large evidence arrays into every signal summary.

Skill-level requirements:

- Store the effective latest-version signal summary used for current moderation.
- Keep this lightweight. Do not copy the full `staticScan.findings` array onto the skill document.

Recommended extra version field:

- `bundleProfile`

```ts
{
  contentProfile: 'docs_only' | 'code_only' | 'mixed'
  hasExecutableFiles: boolean
  hasShellScripts: boolean
  hasOnlyTextLikeFiles: boolean
  hasInstallLikeInstructions: boolean
  inferredSkillCategory: 'security_tool' | 'integration' | 'automation' | 'docs_only' | 'general'
}
```

This should be derived from the bundle and kept small. It is needed so docs-only and security-tool carveouts do not require rescanning file contents everywhere.

### Raw scanner fields to keep during rollout

Do not remove these in Phase 2:

- `skillVersions.staticScan`
- `skillVersions.vtAnalysis`
- `skillVersions.llmAnalysis`
- `skills.manualOverride`
- `skills.moderationVerdict`
- `skills.moderationReasonCodes`
- `skills.moderationEvidence`
- `skills.moderationFlags`
- `skills.isSuspicious`

Phase 2 adds normalized fields; it does not delete existing ones.

### VT storage update

Current `vtAnalysis` is too flat. Phase 2 should update the version-level VT storage shape to preserve both sub-signals:

```ts
vtAnalysis: {
  checkedAt: number
  engines?: {
    status: string
    stats?: {
      malicious: number
      suspicious: number
      harmless: number
      undetected: number
    }
  }
  codeInsight?: {
    status: string
    verdict?: string
    analysis?: string
    source?: string
  }
}
```

Compatibility rule:

- Read old flat `vtAnalysis` rows and normalize them during migration.
- Write only the nested shape after the Phase 2 schema bump.

### Manual override shape

Keep the current moderator mutation limited to `clean` in this phase if product policy does not want moderator-authored `suspicious`/`malicious` yet.

However, the normalized signal model must treat `manualOverride` as future-proof:

- if present, it is a `manual` family signal
- if future schemas allow non-clean overrides, arbitration already supports them

## Reason Code Catalog Changes

## `convex/lib/moderationReasonCodes.ts`

Replace the current flat constants-only approach with a catalog that describes each code:

```ts
{
  code: string
  findingClass: 'security' | 'metadata' | 'context'
  defaultVerdict: 'clean' | 'suspicious' | 'malicious'
  riskTier: 'low' | 'medium' | 'high' | 'critical'
  family: 'local' | 'vt' | 'llm' | 'behavioral'
  suppressibleBy: Array<'docs_only' | 'security_tool_fixture' | 'fixed_binary_exec' | 'declared_vendor_api' | 'localhost_only'>
}
```

Keep the existing string codes, but add metadata-only codes now so future producers have a place to write to:

- `metadata.missing_env_declaration`
- `metadata.undeclared_hook`
- `metadata.install_method_mismatch`
- `metadata.capability_drift`
- `metadata.declared_destination_mismatch`

Rules for aggregate compatibility:

- `skills.moderationReasonCodes` must remain security-only codes that contributed to the aggregate verdict.
- Metadata-only codes live under `moderationSignals.*.metadataCodes` and API signal detail.

## Bundle Profiling and Signal Normalization

## `convex/lib/moderationEngine.ts`

Refactor the engine into explicit stages:

1. `buildBundleProfile(input)`
2. `normalizeStaticSignal(staticScan, bundleProfile)`
3. `normalizeVtSignals(vtAnalysis)`
4. `normalizeLlmSignal(llmAnalysis, bundleProfile, declarations)`
5. `normalizePublisherTrust(owner, skill)`
6. `normalizeManualOverride(skill.manualOverride)`
7. `applySignalSuppressions(signals, bundleProfile, declarations)`
8. `arbitrateSignals(signals)`
9. `buildModerationSnapshot(signals, sourceVersionId)`

### Static scan normalization

Requirements:

- Split static reason codes into:
  - security reason codes
  - metadata codes
  - suppressed codes
- Preserve `staticScan.findings` as the backing evidence for security findings.
- Do not let markdown-only references escalate by default for docs-only bundles.

Expected immediate suppression cases:

- docs-only bundle containing prompt-injection examples or placeholder API-key text
- security tooling fixture/signature content without an execution or exfiltration path
- constrained fixed-binary subprocess usage where execution is clearly non-shell and literal

### VT normalization

Requirements:

- Build two normalized signals:
  - `vtEngines`
  - `vtCodeInsight`
- `vtCodeInsight` suspicious must never be `decisive` by itself.
- `vtEngines` and `vtCodeInsight` share the `vt` family.

Verdict mapping:

- engine stats:
  - `malicious > 0` => `malicious`
  - else `suspicious > 0` => `suspicious`
  - else `harmless > 0` => `clean`
  - else `pending`
- Code Insight:
  - benign/clean => `clean`
  - suspicious => `suspicious`
  - malicious => `malicious`

Contribution defaults:

- `vtEngines.malicious` => `decisive`
- `vtEngines.suspicious` => `corroborating`
- `vtCodeInsight.malicious` => `decisive`
- `vtCodeInsight.suspicious` => `corroborating`
- `vtCodeInsight.clean` => `informational`

Special rule:

- `vtCodeInsight.suspicious` alone cannot produce aggregate `suspicious`.

### LLM normalization

Current limitation:

- `llmAnalysis` is partly structured and partly prose.
- That is enough for a first normalized signal, but not enough to cleanly separate metadata drift from security intent.

Phase 2 requirement:

- Extend the LLM result parser and stored payload so LLM output includes explicit machine-readable reason codes in addition to prose.
- Reuse the existing five dimensions, but derive codes from them.

Add to the parsed response shape:

```json
{
  "signal_codes": ["metadata.capability_drift", "suspicious.unexpected_external_destination"],
  "metadata_codes": ["metadata.missing_env_declaration"]
}
```

If updating the prompt/parser in the same PR is too large, use this fallback:

- map `verdict = suspicious|malicious` into the `llmScan` signal
- treat dimension statuses plus `findings` text as explanatory only
- do not invent metadata/security splits from prose alone

Confidence mapping:

- `malicious + high` => `decisive`
- `malicious + medium/low` => `corroborating`
- `suspicious + high/medium` => `corroborating`
- `suspicious + low` => `informational`

### Publisher trust normalization

Normalize trust as a signal so it is visible, but do not allow it to downgrade a real security verdict.

Rules:

- It is always `informational` in Phase 2.
- It may be used for queue ranking or explanation copy.
- It must not strip reason codes or change a `suspicious` / `malicious` aggregate.

This replaces the current hidden bypass behavior.

### Manual override normalization

Rules:

- Manual override wins over computed aggregation.
- `manualOverride` must be surfaced as a first-class signal with `contribution = decisive`.
- Raw scanner evidence and normalized signals remain stored underneath for auditability.

## Arbitration Rules

Aggregate arbitration happens after normalization and suppression.

### Hard rules

1. Manual override wins.
2. Any decisive malicious signal returns aggregate `malicious`.
3. `vtCodeInsight.suspicious` alone cannot return aggregate `suspicious`.
4. Metadata-only findings cannot return aggregate `suspicious`.
5. Publisher trust cannot reduce a computed `suspicious` or `malicious`.
6. Pending/error transport states never carry forward stale suspicion by themselves.

### Suspicious rules

Return aggregate `suspicious` when any of the following is true:

- there are two or more independent contributor families with `corroborating` or `decisive` suspicious-or-worse signals
- there is an explicit capability mismatch signal plus at least one independent security signal
- there is undeclared dangerous behavior plus one corroborating scanner concern

Independent means distinct families, not distinct keys.

Examples:

- `staticScan.suspicious` + `llmScan.suspicious` => `suspicious`
- `vtEngines.suspicious` + `vtCodeInsight.suspicious` => still one `vt` family, not enough by itself
- `metadata.capability_drift` + `vtCodeInsight.suspicious` => `suspicious`
- `metadata.missing_env_declaration` alone => `clean`

### Clean rules

Return aggregate `clean` when:

- no decisive malicious signals exist
- the contributor family count for suspicious signals is below threshold
- all remaining findings are metadata, suppressed, informational, pending, or error-only

### Arbitration pseudocode

```ts
function arbitrateSignals(signals: ModerationSignals): AggregateResult {
  if (signals.manualOverride?.state === 'ready' && signals.manualOverride.verdict) {
    return fromManualOverride(signals)
  }

  const maliciousSignals = readySignals(signals).filter(
    (signal) => signal.verdict === 'malicious' && signal.contribution === 'decisive',
  )
  if (maliciousSignals.length > 0) {
    return aggregate('malicious', maliciousSignals)
  }

  const contributors = readySignals(signals).filter((signal) =>
    signal.verdict === 'suspicious' || signal.verdict === 'malicious'
      ? signal.contribution === 'decisive' || signal.contribution === 'corroborating'
      : false,
  )

  const contributorFamilies = new Set(contributors.map((signal) => signal.family))
  const hasCapabilityMismatch = hasMetadataCode(signals, 'metadata.capability_drift')
  const hasIndependentSecuritySignal = contributorFamilies.size >= 1

  if (hasCapabilityMismatch && hasIndependentSecuritySignal) {
    return aggregate('suspicious', contributors)
  }

  if (contributorFamilies.size >= 2) {
    return aggregate('suspicious', contributors)
  }

  return aggregate('clean', [])
}
```

## Compatibility and Cleanup Rules

## Remove hidden policy bypasses

Delete or retire these behaviors from the arbitration path:

- `isPrivilegedOwnerForSuspiciousBypass()`
- suspicious-code stripping for admin/moderator-owned skills

If staff-owned fixture skills need special handling, use one of:

- a manual override
- a non-public seed/dev path
- explicit security-tool/docs-only suppression logic

Do not encode owner role as a hidden verdict bypass.

## Legacy fields to keep in sync

After arbitration:

- `moderationVerdict` mirrors the aggregate verdict
- `moderationReasonCodes` contains only contributing security codes
- `moderationSummary` is derived from contributing security codes plus override state
- `moderationFlags` is still produced by `legacyFlagsFromVerdict()`
- `isSuspicious` still maps from `flagged.suspicious`

Compatibility rule:

- Existing clients that only understand `isSuspicious` and `blocked.malware` must continue to work unchanged.

## API and Schema Changes

## `convex/httpApiV1/skillsV1.ts`

Expose per-signal details in both moderation and version security responses.

### Skill moderation payload

Add:

```json
{
  "moderation": {
    "verdict": "clean | suspicious | malicious",
    "signals": {
      "staticScan": { "...": "..." },
      "vtEngines": { "...": "..." },
      "vtCodeInsight": { "...": "..." },
      "llmScan": { "...": "..." },
      "behavioralScan": { "...": "..." },
      "publisherTrust": { "...": "..." },
      "manualOverride": { "...": "..." }
    }
  }
}
```

### Version security payload

Keep the current `security.scanners` block for compatibility, but add:

- `security.signals`
- `security.aggregate`

`security.status` should remain a scanner-availability/status summary, not the skill moderation verdict.

Backward-compatibility rule:

- Existing clients using `security.scanners.vt` or `security.scanners.llm` continue to work.
- New clients use `signals` for arbitration-aware detail.

## Shared client schemas

Update:

- `packages/schema/src/schemas.ts`
- `packages/clawdhub/src/schema/schemas.ts`

Requirements:

- add a reusable signal schema
- add `moderation.signals`
- add `security.signals`
- keep all legacy fields optional during rollout

## File-by-File Implementation Plan

## `convex/lib/moderationReasonCodes.ts`

- Introduce the reason code catalog with class/family/risk metadata.
- Keep existing string constants.
- Add metadata reason codes.
- Change `verdictFromCodes()` so it is only used on already-filtered contributing security codes, not on raw signal output.

## `convex/lib/moderationEngine.ts`

- Add bundle profile inference.
- Add signal normalization helpers.
- Add signal suppression logic.
- Replace flat-code arbitration with signal-family arbitration.
- Ensure stale-state recompute is a pure function of current inputs.

## `convex/skills.ts`

- Replace `buildStructuredModerationPatch()` with signal-aware normalization/arbitration.
- Persist `moderationSignals` on version and skill.
- Remove privileged-owner suspicious bypass.
- Keep legacy fields denormalized from the new aggregate result.

## `convex/vt.ts`

- Preserve AV engine stats and Code Insight separately.
- Write the nested VT raw shape plus normalized signals.
- Stop relying on VT rescan branches to clear stale flags manually; let recompute do it.

## `convex/llmEval.ts`

- Prefer adding machine-readable reason codes to the LLM result.
- Store the richer payload on `llmAnalysis`.
- Trigger skill moderation recompute using the signal-aware path when the latest version is updated.

## `convex/httpApiV1/skillsV1.ts`

- Expose `signals` and aggregate explanations.
- Keep evidence redaction behavior unchanged for public callers.

## `packages/schema/src/schemas.ts`

- Add response validators for normalized signals.
- Keep legacy fields optional.

## `packages/clawdhub/src/schema/schemas.ts`

- Mirror the API contract updates for the client package.

## Migration and Rollout

### Step 1: ship schema + normalization behind compatibility

- Add the new fields and readers first.
- Continue writing legacy aggregate fields.
- Make old rows readable even before the backfill completes.

### Step 2: backfill version-level normalized signals

- Read existing `staticScan`, `vtAnalysis`, `llmAnalysis`, and `manualOverride`.
- Populate `skillVersions.moderationSignals` and `bundleProfile`.
- Populate `skills.moderationSignals` for the latest version only.

### Step 3: recompute aggregate moderation for latest versions

- Rebuild `moderationVerdict`, `moderationReasonCodes`, `moderationSummary`, `moderationFlags`, and `isSuspicious`.
- Emit counters for:
  - verdict changed to clean
  - verdict changed to suspicious
  - verdict changed to malicious
  - stale-state cleared
  - docs-only suppression applied
  - security-tool suppression applied
  - VT Code Insight-only suspicion suppressed

### Step 4: run full rescan/backfill

- Run the existing VT and LLM backfill paths after the normalized model lands so current raw inputs are refreshed.
- Keep rescan idempotent; the aggregate must always be rebuilt from current source data, not patched incrementally.

### Engine versioning

- Bump the moderation engine version when the new arbitration model ships.
- Recommended version: `v3.0.0`.

## Test Plan

Add or update tests in:

- `convex/lib/moderationEngine.test.ts`
- `convex/vt.test.ts`
- `convex/httpApiV1.handlers.test.ts`
- relevant `convex/skills.*.test.ts` files

Required cases:

- VT Code Insight suspicious alone => aggregate `clean`
- VT engines suspicious + LLM suspicious => aggregate `suspicious`
- VT engines suspicious + VT Code Insight suspicious => still not enough by themselves
- static suspicious + metadata drift => aggregate `suspicious`
- metadata drift alone => aggregate `clean`
- docs-only prompt-injection examples remain `clean`
- security-tool signature fixture without execution path remains `clean`
- fixed-binary non-shell subprocess remains `clean`
- explicit exfiltration + LLM suspicious => aggregate `suspicious`
- known blocked signature => aggregate `malicious`
- current clean VT/LLM plus stale old suspicious state => recompute to `clean`
- manual override remains decisive after rescans
- public API returns signals while preserving legacy fields

Golden corpus requirement:

- Add a representative false-positive set from the open issue buckets called out in the umbrella plan.
- Add a representative known-malicious set.
- Block rollout if any known-malicious sample becomes `clean`.

## Acceptance Criteria

This phase is complete when all of the following are true:

- aggregate verdicts are derived from normalized signals, not a flat merged code list
- `vtEngines` and `vtCodeInsight` are stored and exposed separately
- metadata-only findings no longer make a skill aggregate `suspicious`
- privileged-owner suspicious bypass is removed from the engine
- stale suspicion clears on recompute without bespoke rescan patch logic
- API clients can read per-signal detail without breaking legacy callers
- the first bulk recompute materially clears the known false-positive buckets named in the umbrella plan

## Open Decisions

These decisions should be made before implementation starts, not during code review:

- whether the LLM prompt/schema bump for machine-readable codes ships in the same PR as the arbitration engine or one PR later with a fallback mapping
- whether manual override remains `clean`-only in the stored schema during Phase 2 or becomes future-proof immediately
- whether `bundleProfile` is stored as a durable field or recomputed during normalization and only cached on versions during backfill
