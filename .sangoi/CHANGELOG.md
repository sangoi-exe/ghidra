# Local fork changelog

## In progress — safe profiles and new RE candidates

- Correct overflow in both MCP pagination helpers. Twelve focused tests pass after the two demonstrated failures, and actual stock-bridge stdio requests to both pagination paths return the exact 1,029-item slice from 1,030 items with offset 1 and limit 2147483647.

- Qualify operand/address context at every recognized helper instruction and at the memset wrapper's actual internal target. Native incompatible-context cases are rejected without applying their operational contracts; existing helper/caller validators pass.

- Preserve conflicting defined data across its full native mutation footprint. Apply profile data before inference and final function facts afterward. The narrow native switch-markup correction preserves arrays/structures/references and passes seven tests. All eight original automatic profile validators pass on the corrected private runtime.

- Separate original identity from current function qualification. Verify bytes, native relocation expectations and effective context before applying original cleanup. Preserve manual VPRINTER flow and TLINK dependent contracts. Actual RET0/context/relocated-field counterexamples and restored-original controls pass.

- Implement the whole 128-byte move family and selected BCC 2.0/3.1/4.5 facts in `218a8564f617185cb9e0820d74b8fff7b361f32d`. Cumulative native validation passes all eight originals and the helper suite. Actual MCP queries consume 21 selected new functions, seven C views and the two descriptive record types. The [current plan](planning/2026-10-15-safe-legacy-profile-candidates.md) owns the single delivery; the [execution record](task-logs/2026-10-15-safe-legacy-profile-candidates.md) records attempts and limits. Code Gate selection/review remains pending. No global deployment or push occurred.

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
