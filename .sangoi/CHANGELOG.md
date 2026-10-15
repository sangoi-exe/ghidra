# Local fork changelog

## In progress — integrated toolchain analysis and segmented C

- Record the user-confirmed single-delivery expansion: qualified compiler/tool profiles, runtime helpers, call/reference analysis, structural NB02 recognition and necessary decompiler-core corrections for segmented-memory C expressions.

- Implement eight qualified exact-image profiles, complete-body runtime helpers, native NE provenance and structural NB02 observations in the independent extension. All current profiles pass automatic native validation, including corrected shared-entry ownership and retained UNKNOWN cleanup.

- Correct selector-dependent C and actual segmented call-argument reads in the decompiler. Focused native units8/8 and data assertions92/92 pass, together with named real helper/writer cases and nonsegmented controls. Correct native MZ detection for the supplied BCC2.0 image; four native tests and ordinary import pass.

- Build matching Ghidra12.3 DEV and both extensions without global installation. Copy the MCP product sources into `extensions/ghidra-mcp/` with retained upstream layout/license and localized API/build adaptation. Native compilation/version checks pass; selected Java tests pass across the main run and a focused temporary-path rerun, and Python reports1095 passed/nine platform skips. Actual copied-bridge analysis, all three formerly failing C queries and saves now pass on private Programs. The user-selected local Code Gate remains pending; no completion review pass or remote push is claimed.

## Unreleased — extension placement correction

- Version the validated legacy-toolchain extension under `extensions/ghidra-legacy-toolchains/` in this fork instead of requiring a separate repository.

- Add its native standalone Gradle settings boundary, retaining the module/project identity without changing the parent Ghidra build.

- Preserve validated runtime/source bytes and provide current module usage/validation guidance. Native build, source ownership and runtime-payload comparisons pass; prior behavior evidence is reused only for identical payload.

- Complete local Code Gate review with `PROCEED`, no findings or nits, and full coverage of all fourteen changed paths. Closeout records the reviewed result without changing module bytes. No remote push or deletion of the historical source repository has occurred.
