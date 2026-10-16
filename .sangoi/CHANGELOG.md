# Local fork changelog

## In progress — safe profiles and new RE candidates

- Correct overflow in both MCP pagination helpers; the two reproduced maximum-limit failures now pass within 12 focused tests. Checkpoint `c85f7d109215112a8d109f50a8595e0de447be84` is not yet integration-reviewed.

- Qualify operand/address context at every recognized helper instruction. Native F_SCOPY internal-context cases are rejected, the normal control is accepted, and existing helper/caller validators pass. Checkpoint `3e86200e17f3046ae77e2806e0c77366b2080d28` does not close the separately unverified memset-target check.

- Stop the data-preservation slice after direct proof passes but fresh automatic SimTower profile completion fails on data created before the late profile pass. The user selected separate early data preparation and late function/contract application within the existing extension. The [current plan](planning/2026-10-15-safe-legacy-profile-candidates.md) records that sequencing amendment, not an implemented correction; the [execution record](task-logs/2026-10-15-safe-legacy-profile-candidates.md) preserves the evidence and incomplete state. New candidates, final Code Gate, deployment and push remain unfinished or unauthorized as recorded there.

## Unreleased — integrated toolchain analysis and segmented C

- Record the previous Johnny/SimTower commit-screening limits and useful evidence in [the local commit-frontier report](reports/2026-10-15-re-commit-frontier.md). Screen19/22 subsequent local subjects at fixed tips, distinguish selected semantic review from subject coverage, and retain new helper/profile candidates without automatically adding them to implementation Scope.

- Record the user-confirmed single-delivery expansion: qualified compiler/tool profiles, runtime helpers, call/reference analysis, structural NB02 recognition and necessary decompiler-core corrections for segmented-memory C expressions.

- Implement eight qualified exact-image profiles, complete-body runtime helpers, native NE provenance and structural NB02 observations in the independent extension. All current profiles pass automatic native validation, including corrected shared-entry ownership and retained UNKNOWN cleanup.

- Correct selector-dependent C and actual segmented call-argument reads in the decompiler. Explicit compiler-stack selector metadata now replaces the CALL-local STORE inference, including the reproduced JMP/CALL_RETURN case. Native units209/209, focused data assertions92/92 and two actual Java/native integration tests pass; synthetic bookkeeping stays offset-only. The earlier native MZ correction retains its four-test and ordinary BCC2.0-import proof.

- Build matching Ghidra12.3 DEV and both extensions without global installation. The in-repository MCP copy retains upstream layout/license and localized API/build adaptations. Its unchanged earlier selected Java/Python unit proof remains bounded to that source. Fresh copied-bridge analysis, all three exact C queries and saves pass again on the corrected SDK; all five returned C strings equal the prior successful port results. Both canonical extension packages build against that SDK with unchanged runtime payloads apart from generated MCP build timestamps. The final local Code Gate returned `PROCEED` for candidate `a8e12c3925285a287d955ded2516691061e9aa09`, with complete correction/follower coverage and closure of the earlier regression. The earlier `DO_NOT_PROCEED` remains historical truth. No remote push or global deployment occurred.

## Unreleased — extension placement correction

- Version the validated legacy-toolchain extension under `extensions/ghidra-legacy-toolchains/` in this fork instead of requiring a separate repository.

- Add its native standalone Gradle settings boundary, retaining the module/project identity without changing the parent Ghidra build.

- Preserve validated runtime/source bytes and provide current module usage/validation guidance. Native build, source ownership and runtime-payload comparisons pass; prior behavior evidence is reused only for identical payload.

- Complete local Code Gate review with `PROCEED`, no findings or nits, and full coverage of all fourteen changed paths. Closeout records the reviewed result without changing module bytes. No remote push or deletion of the historical source repository has occurred.
