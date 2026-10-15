# Local fork changelog

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
