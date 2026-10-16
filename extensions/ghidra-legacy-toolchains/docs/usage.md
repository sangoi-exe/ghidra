# Build and use

## Supported analysis

`Legacy toolchain exact-image profiles` registers the following profiles. Qualification requires the native executable format and complete retained original `FileBytes` identity (size and SHA-256), not a filename, version string or relocated-memory comparison.

| Qualified input | Native import | Profile ID |
| --- | --- | --- |
| BCC 2.0 | MZ | `bcc20-qualified` |
| BCC 3.1 | NE | `bcc31-qualified` |
| BCC 4.5 | NE | `bcc45-qualified` |
| TASM 3.1 | MZ | `tasm31-qualified` |
| TLINK 4.01 | MZ | `tlink401-qualified` |
| TLINK 5.1 | NE | `tlink51-qualified` |
| Supplied SCRANTIC image | NE | `scrantic-runtime-qualified` |
| Supplied SimTower image | NE | `simtower-runtime-qualified` |

The profiles add selected native layouts, enums, labels, complete functions and qualified references. Automatic execution prepares qualified data and its static bindings at native format-analysis priority, then queues final code extents, cleanup and function contracts after ordinary inference. The native analysis queue owns both phases; the complete profile is not replayed twice. Direct callers invoke the same `prepareData` and `applyFinalFacts` owners in that order. BCC 2.0's static overlay projections precede facts that require those mappings.

Shared profile operations check original-file mapping and preserve higher-priority user annotations rather than treating imported coordinates as universal addresses. Data application preserves exact-equivalent definitions; conflicting defined units, including units crossing a requested boundary, are refused before clearing, retaining their full extents and references even without a user label. A preparation failure does not queue final application. A queued final phase is not completed application: native validators drain the queue and require its successful completion before checking rerun effects. Profile failures appear in the native analysis log and warnings; aggregate headless analysis success alone does not prove profile completion. Undefined fields, incomplete function extents, unobserved runtime state and unproved subordinate effects remain explicit in the annotations.

Original-image identity does not qualify the current code. Before the shared function owner applies bodies or cleanup, it compares current bytes with original bytes plus independently resolved native MZ/NE relocation writes and checks the effective 16-bit operand/address context. Patched instructions or relocation operands are refused without reapplying the original contract. Unsupported loader evidence is not ignored. The native NE parser and original target/import identity remain authoritative; the extension does not retain another loaded-image baseline. `FunctionApplication` explicitly reports applied versus preserved. Preserved VPRINTER and TLINK writer functions do not receive their dependent flow or writer-contract edits. The shared owner retains manual comment text and can append a preservation notice. These checks protect profile operations; they do not prevent independent native reanalysis triggered by other edits or prove opaque callee behavior.

TLINK 5.1 keeps its six selected FAR-slot functions out of early data preparation. The other 99 raw slots remain data; the original 105-position, 97-EA/8-FF accounting is unchanged. Final application qualifies the six code slots without clearing them first. The eight-range error function also uses the shared current-code qualifier and excludes all 89 inline-data bytes. Its seven conditional inline-return flow, reference and caller-comment edits require accepted applications of both helpers and the shared body. A preserved prerequisite leaves those caller facts unchanged and produces an explicit skipped-edits log. Supported independent facts can still apply; profile refusal does not promise rollback of unrelated facts or repair of a modified Program.

BCC 2.0 includes static file-backed overlay projections and qualified joins. These are analysis views of retained bytes, not an implementation of runtime overlay residency, selector assignment or overlay execution. TASM/TLINK state-dependent descriptions distinguish stored defaults from actual invocations. TLINK's selected writer contract includes an analysis-only CF/DX/CX/ES result and near-return frame; it is not a historical return type, physical-I/O success contract or proof of all caller propagation.

BCC 2.0 also represents the complete R357/R363 selector/operand bodies and the R335 conditional zero-to-self-XOR path, retaining shared SUB/XOR dispatch and partial backend coverage. BCC 3.1 represents the complete R329/R333 record-preparation and R320 lowering bodies, their separate tables and real calls; its byte-complete containing parent has explicitly partial semantic coverage. Fresh frame/child reads do not imply pointer identity, purity or a recovered source type. BCC 4.5 adds the RF26/RF30/RF31 pending-selector, cache-query, constant-record and serialization facts. `PendingEntry9` is a descriptive type without an invented heap instance. The AL-only cache query, literal `ax,ax,` output and direct frontend 003E construction remain distinct; they do not establish RF24 allocation history or 0039-to-003E rewriting.

SCRANTIC includes qualified LSEEK and heap-member correspondences. SimTower includes selected startup, SPRF/VPRINTER, EXIT and XXV correspondences. Supplier names and binding roles are descriptive candidates, not retained debug symbols, release-exclusive signatures, modern library ABIs or full transitive runtime models.

### Complete-body helpers

These separately enabled analyzers require complete evidenced bytes, native instruction boundaries and 16-bit operand/address context. They accept native x86 16-bit Protected Mode and Real Mode language IDs; actual application validation covers the selected native NE imports, not general Real Mode execution. Higher-priority function contracts are retained.

| Analyzer | Qualified contract |
| --- | --- |
| `Borland F_SCOPY (qualified 16-bit)` | Complete 28-byte body; implicit `CX:2` count, source at entry stack `+4`, destination at `+8`, analysis `void`, argument purge 8 and far-return size 4 (total extrapop 12). |
| `Borland far copy (qualified 16-bit)` | Complete 38-byte body; destination/source offset-selector records and WORD count on the caller-owned stack, `DX:AX` record result, purge 0 and far-return size 4. |
| `Borland fmovmem (qualified 16-bit)` | Complete 89-byte core, qualified with its adjacent wrapper as one 128-byte family; source/destination records and WORD count, analysis `void`, purge 0 and far-return size 4. |
| `Borland fmemmove (qualified 16-bit)` | Distinct 39-byte wrapper in the same qualified family; destination/source records and WORD count, fresh post-call `DX:AX` result, purge 0 and far-return size 4. |
| `Borland far pointer compare (qualified 16-bit)` | Complete 33-byte F_PCMP correspondence; normalized finite-word comparison of `DX:AX` and `CX:BX`, analysis-only nine-byte ZF/AX/DX/BX/CX result. ZF is not raw input-pair equality and AX is not boolean. |
| `Borland setmem (qualified 16-bit)` | Complete 40-byte internal fill body; WORD destination offset, count and fill input, WORD AX result, caller-owned six-byte argument frame. |
| `Borland memset (qualified 16-bit)` | Complete 29-byte fill wrapper; WORD destination offset/count/fill storage and result, not a host-pointer prototype. |
| `Borland word-pair shifts (qualified 16-bit)` | Left, arithmetic-right and logical-right far cores with `DX:AX` value/result and `CL` count; mathematical qualification covers counts 0..31. Actual near adapters retain labels rather than manufactured overlapping functions. |

`/LegacyToolchains/Borland/FarAddress16` contains a two-byte `offset` followed by a two-byte `selector`. It preserves storage, not selector mapping or a flat pointer. Helper prototypes declare qualified preservation/clobbers, but do not calculate all changed registers, exact copy/fill memory effects, faults or arbitrary frame aliases. Shared helper bytes do not elect an exclusive compiler release or historical spelling.

The move family qualifies both complete bodies, per-instruction context and the actual wrapper PUSH-CS/near-CALL relationship before applying either operational contract. Its raw selector/offset direction choice and modular backward copy do not implement unrestricted modern `memmove`. BX is clobbered, unlike the separate forward copier. The observed original caller reloads its own destination pair after the wrapper call; that caller does not prove consumption of the wrapper's returned pair.

An image can contain more than one complete helper match. The supplied SimTower image has two qualified move-family copies. Use an explicit native function address when an MCP name query is ambiguous; the analyzer does not assume that a shared helper name uniquely identifies one address.

### Provenance and debug structure

`NE relocation provenance (qualified 16-bit)` adds EOL comments relating native relocation raw fields, chain heads, individual applications, original/current bytes and uniquely qualified instruction operand masks. It does not add reference edges, infer runtime binding or repair the native loader's remaining unsupported-type/additive limitations.

`NB02 initial/footer structure` observes complete 16-byte initial-shaped records and terminal eight-byte footers in original `FileBytes`, including the qualified retained-end-minus-distance relation. Reports live in Program Information options with prefix `Legacy toolchains NB02 structure.FileBytes `. Mapped records can receive comments; unmapped records remain file observations, with no invented memory. This is not a complete debug-directory, symbol or type parser, nor evidence that other debug information was removed or absent.

## Build a matching runtime and extension

The integrated target is this fork's Ghidra 12.3 DEV with JDK 25. Private build evidence used JDK 25.0.2 and Gradle 9.7.1. Ghidra 12.1.4/JDK 21 evidence belongs to the historical first increment, not the current compatibility target.

Build the matching fork distribution first using Ghidra's native dependency/build machinery; see the fork's [Developer Guide](../../../DevGuide.md). From a prepared source root, `gradle assembleAll` produces an unpacked native distribution under `build/dist/`. Native dependencies and platform toolchains are prerequisites. A task-private source export keeps native outputs away from the working source tree. Do not substitute a changed 12.3 decompiler executable into a 12.1.4 distribution.

Export `JAVA_HOME` for JDK 25 and `GHIDRA_INSTALL_DIR` for that matching distribution. Then build the standalone extension, not a new root-build module:

```bash
cd extensions/ghidra-legacy-toolchains
mkdir -p "$HOME/.cache/codex"
work=$(mktemp -d "$HOME/.cache/codex/ghidra-legacy-toolchains-XXXXXX")
mkdir -p "$work"/{tmp,home,config,cache,data,prefs/user,prefs/system}
export HOME="$work/home" TMPDIR="$work/tmp"
export XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$work/cache" XDG_DATA_HOME="$work/data"
export GRADLE_USER_HOME="$work/gradle-home"
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME -Djava.io.tmpdir=$TMPDIR -Djava.util.prefs.userRoot=$work/prefs/user -Djava.util.prefs.systemRoot=$work/prefs/system"
gradle --no-daemon --project-cache-dir "$work/project-cache" -PbuildOutputDir="$work/build" buildExtension
```

The extension uses the selected distribution's `support/buildExtension.gradle`. `buildOutputDir` redirects dependency-copy, source-archive and extension ZIP outputs; the ZIP is under `$work/build/dist/`. Building the extension does not rebuild or patch Ghidra itself, and does not install anything globally.

## Load in a private native process

Keep the private environment above. Set `extension_zip` to the freshly built ZIP, then unpack it into the private 12.3 settings tree:

```bash
mkdir -p "$XDG_CONFIG_HOME/lucas-ghidra/ghidra_12.3_DEV/Extensions"
unzip "$extension_zip" -d "$XDG_CONFIG_HOME/lucas-ghidra/ghidra_12.3_DEV/Extensions"
module="$XDG_CONFIG_HOME/lucas-ghidra/ghidra_12.3_DEV/Extensions/ghidra-legacy-toolchains"
```

The module contains `Module.manifest`, `extension.properties`, `data/`, `lib/` and `ghidra_scripts/`. This private native headless installation is the current loading route; GUI installation has not been tested. After rebuilding, use a fresh private configuration/cache tree and install the new ZIP there: source-ZIP timestamps can otherwise leave stale OSGi script classes. Restart Ghidra after extension or native-core changes; changing files under a running process is insufficient.

Import originals with native `MzLoader` or `NeLoader` detection and leave native analysis enabled. The fork's MZ parsed-header correction is required for ordinary BCC 2.0 import; no alternate loader or executable format is introduced. Do not force a raw-binary import to select a profile. Helper priorities follow the generic segmented calling-convention pass so that it does not overwrite their more specific frame contracts.

For a project parent under a dot-prefixed cache path, keep a directory descriptor open in the launching shell and pass `/proc/$$/fd/9` to `analyzeHeadless`. This Linux route avoids Ghidra's hidden-project-path rejection without creating an outside-cache symlink; the descriptor path is valid only while that shell remains alive. See the [focused validation command](validation.md#focused-native-checks).

## Consume through the existing MCP

The extension adds no MCP endpoint or transport. The sibling [in-repository MCP 7.0.0 port](../../ghidra-mcp/README.md#in-repository-ghidra-123-port) supplies the existing native headless entrypoint and stdio Python bridge, built independently against the matching 12.3 SDK/JDK 25. Its localized API adaptations resolve the earlier SLEIGH C-query failure; actual MCP analysis and saves passed for three Programs, with nonempty C returned for five selected functions. Python protocol/transport files are unchanged from upstream; `.refs/ghidra-mcp` is reference material, not a build/runtime dependency. Earlier 12.1.4 MCP proof remains historical only. Use the sibling's existing build/setup mechanisms; the standalone launch route uses matching Ghidra jars, the extension JAR on the classpath and `ghidra.external.modules` pointing to the unpacked module. Headless startup is observed; GUI installation/startup remains unverified.

Before discovery, inspect existing UDS candidates outside the private tree. The bridge scans all candidates and may remove stale sockets, so private XDG variables or a supplied URL alone do not isolate it. Do not touch another instance; verify the exact private PID, socket, project and program before analysis, script execution or save.

1. Initialize MCP, inspect `tools/list` and verify `list_instances` identity. Supply an explicit program project path on each program operation.

2. Use `run_analysis` with `program`, then `list_analyzers` to inspect the enabled analyzer names above. An immediately opened program can have an empty analyzer list until native options are initialized; that alone does not prove the extension is absent.

3. Read native contracts and the C view through `get_functions`, selecting `signature,parameters,decompiled_code` in `fields`. The previously failing query argument sets now pass on the matching SDK; this proves consumption of the selected results, not complete endpoint coverage or generalized semantic correctness. Inspect types with the existing type operations when needed.

4. The existing `run_ghidra_script` schema accepts the installed script's absolute path in `script_name` and whitespace-separated `args`. It requires `GHIDRA_MCP_ALLOW_SCRIPTS=1`; argument paths must not contain spaces. NB02's custom options need a script observation rather than the bridge's ordinary program metadata dictionary. Current 12.3 script execution through MCP remains unverified.

5. Call `save_program` after changes and re-read the saved native results. Analysis and validator scripts mutate Programs: use a task-owned project, not an existing user's analysis project.

An explicit MCP import `language` selects the raw-binary loader; it is not an NE profile override. `get_function_pcode`, including `basic` mode, returns HighFunction operations, not raw `Instruction.getPcode()` output. Use native scripts when instruction-level p-code or file provenance is required. Detailed bridge startup and transport behavior remain owned by the MCP project.

## Semantic limits

The fork's native decompiler emits address-valued typed segment operations with selector and offset dependencies in the C view. This is analysis syntax, not historical source C, guaranteed host-compilable C, a runtime selector resolver or proof that every segmented-memory operation is represented faithfully. Inspect raw instruction p-code, HighFunction and the original bytes alongside C. The demonstrated fill-wrapper call now uses actual selector-qualified argument reads rather than unrelated abstract stack inputs; this is not general store forwarding or validation of arbitrary segmented call forms. The successful MCP C queries do not broaden these native qualifications; remaining proof gaps are recorded in [validation status](validation.md#current-correction-evidence).

The extension does not replace original-byte reconstruction, compilation and comparison. No full corpus, complete ABI/transitive runtime model, original compiler/linker/game execution, general Real Mode execution, whole-game recovery or complete memory-model support is claimed.
