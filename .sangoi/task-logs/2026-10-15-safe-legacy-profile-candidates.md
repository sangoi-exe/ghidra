# Safe legacy profile candidates — execution record

Canonical intent: [safe legacy profiles and qualified RE candidates](../planning/2026-10-15-safe-legacy-profile-candidates.md). This log records execution and observations; it owns no Scope or implementation authority.

## Current state

The user activated the approved Implementation with `sim, favor`, turn `01a1422f-1bb8-70e2-87a8-f16b2ba116eb`, at `2026-10-15T21:49:06.346-03:00` (`America/Sao_Paulo`). Product baseline is `3bb77e8dabb13abeb6f40f6a767e48b69d8725cd`; planning checkpoint is `150730fed19208d21c8043e3808961b6ee8eccc0`. New product outputs are under `/home/lucas/.cache/codex/safe-legacy-candidates-fuo2mE/`.

Two bounded corrections are checkpointed with focused proof. Data preservation passes direct native proof but breaks required fresh automatic profile completion. That failing slice remains uncommitted and has not been deployed. No new candidate capability has started. The current-code/purge and dependent VPRINTER-flow fixes remain unimplemented. No Code Gate has been selected or run for this task.

## M2: pagination correction

Worker `/root/safe_mcp_pagination_impl` changed only `ServiceUtils.java` and its existing `ServiceUtilsPagedTest.java`. Both slicing methods now perform addition as `long`, clamp to the actual list size, then narrow. Request/response shape and offset/unbounded-limit policies are unchanged. Checkpoint: `c85f7d109215112a8d109f50a8595e0de447be84`.

Canonical Gradle test execution compiled actual production/test sources against the matching SDK. Before correction, 12 tests ran with exactly two failures: the maximum-limit counterexample in each real method. After correction, all 12 passed with zero failures, errors or skips. Root inspected the complete patch and red/green XML. Actual MCP transport remains pending. Evidence: `pagination/gradle-{red,green}.log`, `pagination/ServiceUtilsPagedTest.{red,green}.xml` under the task cache.

## M3: shared helper-context correction

Worker `/root/safe_helper_context_impl` moved the existing opsize/addrsize check into the per-instruction loop in `QualifiedRuntimeHelperAnalyzer`. The existing `ValidateFScopy.java` now constructs native predecoded fixtures from the actual original helper and verifies effective context, p-code, acceptance/rejection and no prototype installation for rejected cases. Checkpoint: `3e86200e17f3046ae77e2806e0c77366b2080d28`.

The old owner plus new validator failed at the demonstrated internal opsize acceptance. With the correction, the normal two-byte MOVSW fixture was accepted; internal opsize 1/MOVSD and addrsize 1/ESI-EDI fixtures were rejected without a function/contract/prototype and retained their decoded p-code. Existing SimTower F_SCOPY/far-copy and SCRANTIC F_PCMP/fill/word-pair-shift validators explicitly passed. Both fresh imports completed analysis, post-analysis and save. These helper checks do not establish full exact-profile completion. Root checked the complete diff and native evidence.

Evidence: `helper-context/logs/build.log`, `red-stdout.log`, `green-simtower-stdout.log`, `green-scrantic-stdout.log`, and `helper-context/validation/fscopy/internal-context.txt`. The green logs contain no ERROR; SimTower reports three existing DataTypeArchive template warnings. A later non-substantive correction removed a nested ternary from evidence formatting; a bounded Java check proved identical strings for all three scenarios (`logs/evidence-formatting.log`). Native semantic checks were not rerun for that equivalent formatting change.

The initial brief incorrectly named SCRANTIC for the SimTower-specific F_SCOPY validator. The Worker found the mismatch before execution, and root authorized the correct retained SimTower original without retargeting the validator. No result uses the wrong input.

## M1 reassessment: preserving data versus automatic completion

### Required invariant and baseline

Both requirements remain binding: conflicting manual data must retain its complete type/extent/references, and fresh qualified automatic imports must still receive the supported profile facts. The original `Context.data` cleared intersecting units and therefore cannot be restored as a valid correction. Its earlier successful automatic profile results are a behavioral comparison, not permission to retain manual-data loss.

Known original failure evidence is `/home/lucas/.cache/codex/legacy-findings-verification-bJUZ9N/native-findings.log`. Native Listing/CodeManager clearing expands to complete intersecting units and removes references. The original guard inspected only the requested range and exact-start data. Defined data has no source-priority ownership that would establish disposal authority when a USER_DEFINED symbol is absent.

### Attempt ledger and retained learning

One correction attempt has been made. Worker `/root/safe_profile_data_impl` changed only `ToolchainProfile.java` and `ValidateSimTowerRuntimeProfile.java`. The exact-equivalent fast path remains. Non-equivalent application expands the ownership-check footprint to containing boundary units and visibly refuses conflicting defined data before clearing. The validator protects crossing, unsymbolized, tail-crossing and inside-symbol cases, references at both ends, equivalent-data idempotence, and production refusal without a false Applied log.

The full extension build passed. Fresh direct native SimTower validation passed all existing 28 selected-function checks plus the new preservation controls. Evidence: `data-preservation/logs/build.log`, `logs/direct-stdout.log` and `direct/simtower-runtime-profile-validation.txt`.

The first automatic run then failed acceptance: the validator could not find `simtower_xxv_raw_table42`. A cache-only native probe found `/undefined2` units at FILE 0x65030 onward and a 45-byte `/string` at native 1288:004b–0077, extending two bytes beyond the requested startup region's end 0075. The production analyzer returned false with `preserving conflicting defined data /undefined2 at 1288:0030 through 1288:0031`. Additional observed conflicts include the individually defined 24-word dispatch table and NULL-fallback string. Evidence: `data-preservation/logs/automatic-stdout.log:164` and `logs/automatic-probe-stdout.log:52–110`.

Headless reported overall Analysis succeeded despite this profile's failure. The explicit profile marker/assertions and analyzer return are the relevant acceptance evidence; process exit or aggregate analysis success is insufficient. No manual data was overridden to make the run pass.

Stop trigger: one correction repaired the demonstrated preservation defects but broke another required behavior on the same application path. No second patch or speculative fix stack followed. The data Worker stopped with `FRONTIER_EXPANSION_REQUIRED`; root preserved both changed files and the disposable evidence. These two files are deliberately not checkpointed as a working implementation.

### Current owner chain and evidence

Read-only `/root/safe_profile_order_recon` traced the existing scheduling path. `ToolchainProfileAnalyzer` runs the entire profile at priority 10002. Native constant-reference data inference, strings and switch-table analysis have earlier priorities. The native NE loader does not define these ordinary segment scalars/strings; its string data creation is limited to resource string tables. The successful direct import/application and failed automatic result support the post-import conflict. Exact per-address creator attribution was not instrumented and remains unproved.

Moving the complete profile earlier is not an established closure. `X86FunctionPurgeAnalyzer` runs at function-analysis priority, and `FunctionPurgeAnalysisCmd` recomputes unknown cleanup values. The current late batch intentionally retains qualified UNKNOWN values and function boundaries. `scheduleWorker(..., false, ...)` suppresses new change events only; it does not remove already queued analysis. Root directly inspected this path. Earlier whole-profile application has not been validated and is not selected.

The current causal frontier is the existing profile application sequence: early data definition before inference versus late function/contract facts after inference, across the current profile consumers and validators. No loader/core change or new process is indicated. The user selected this responsibility split in the decision below; it remains unimplemented. Replaying the whole profile twice or weakening data preservation is not selected.

### Selected decision and one next verification

The assistant proposed separate early data preparation and late function/contract application within the existing extension/native analysis queue, with direct profile/validator propagation. The user selected that proposal with `sim`, turn `01a14248-7217-7791-9834-a306b2c6784f`, at `2026-10-15T22:16:46.847-03:00`, source-session line 7544, following the exact paraphrase at line 7537. The confirmed preservation/current-code requirements and all four candidate groups remain unchanged. The canonical plan records the internal sequencing amendment.

The local Plan Auditor on `/root/safe_legacy_candidates_plan_audit` returned `PROCEED` for Doctrine / Plan amendment, with full contract-field coverage and no material findings or required evidence-blocked fields. It confirmed the stable Scope/strategy boundaries and the immediate end-state oracle. The reviewer did not rerun tests or approve implementation. Root recorded the registered hold transition; later current-user implementation authorization remains required before implementing the selected division.

After the planning/implementation checkpoints close, the next verification is one fresh automatic SimTower import using the existing full profile validator and preservation controls. It must establish both the required final data/function facts and unchanged conflict preservation. Do not add an independent trace framework or repeatedly reapply the whole profile merely to get a green result.

## Remaining evidence and implementation frontier

- `/root/safe_current_code_recon` established that native FileBytes retains original bytes and the latest modified layer, not an intermediate post-loader baseline. MZ relocation values retain the fixed-up segment; NE tuples retain raw target fields, not a universal resolved target. A relocation's APPLIED status cannot exempt its bytes from patch qualification. Actual relocation-class coverage across the existing qualified function bodies has not yet been inventoried; current-code qualification is not implemented.
- All eight retained original paths were recovered from previous successful validator logs and remain readable with expected sizes. Their current native content matches were not rerun. These locators do not broaden the fixed candidate source frontiers.
- `BorlandSetmemAnalyzer.requireQualifiedTarget`, used by the memset wrapper, has a separate entry-only target-context check. This is an unverified direct-follower concern, not a new executed defect. A bounded native witness is needed before claiming or implementing its correction. No current acceptance claim includes that adverse case.
- VPRINTER preserved-flow handling, all four new candidate groups, updated product documentation/packages, actual MCP transport integration and the final selected Code Gate remain unfinished.

All native work used fresh task-owned cache outputs and the existing matching SDK/JDK. No global installation/configuration, user-project mutation, original-program execution, external upload or push occurred. Completed helper/pagination commits are interim checkpoints, not a completed or reviewed delivery.
