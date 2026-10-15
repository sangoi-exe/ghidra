# Local fork changelog

## In progress — integrated toolchain analysis and segmented C

- Record the user-confirmed single-delivery expansion: qualified compiler/tool profiles, runtime helpers, call/reference analysis, structural NB02 recognition and necessary decompiler-core corrections for segmented-memory C expressions.

- Implement eight qualified exact-image profiles, complete-body runtime helpers, native NE provenance and structural NB02 observations in the independent extension. All current profiles pass automatic native validation, including corrected shared-entry ownership and retained UNKNOWN cleanup.

- Correct selector-dependent C and actual segmented call-argument reads in the decompiler. Focused native units8/8 and data assertions92/92 pass, together with named real helper/writer cases and nonsegmented controls. Correct native MZ detection for the supplied BCC2.0 image; four native tests and ordinary import pass.

- Build matching Ghidra12.3 DEV and the extension without global installation. Existing MCP7.0.0 analyzes and saves the three private test Programs, but its C-query consumer references an incompatible SLEIGH API. The user selected a tracked source copy under `extensions/ghidra-mcp/`, with localized API/build adaptation rather than a separate fork or patch procedure. Its Strategy-reset Plan Gate returned `PROCEED` without findings; subsequent implementation authorization remains pending and no MCP source has been copied. Completion Code Gate and successful MCP C-query proof are not complete; no completion review pass or remote push is claimed.

## Unreleased — extension placement correction

- Version the validated legacy-toolchain extension under `extensions/ghidra-legacy-toolchains/` in this fork instead of requiring a separate repository.

- Add its native standalone Gradle settings boundary, retaining the module/project identity without changing the parent Ghidra build.

- Preserve validated runtime/source bytes and provide current module usage/validation guidance. Native build, source ownership and runtime-payload comparisons pass; prior behavior evidence is reused only for identical payload.

- Complete local Code Gate review with `PROCEED`, no findings or nits, and full coverage of all fourteen changed paths. Closeout records the reviewed result without changing module bytes. No remote push or deletion of the historical source repository has occurred.
