# Build and use

## Supported result

The analyzer `Borland F_SCOPY (qualified 16-bit)` matches the complete evidenced 28-byte helper in initialized executable memory. It verifies native instruction boundaries and 16-bit operand/address context before applying a function contract. It does not identify an exclusive Borland release: the inspected 3.1 and 4.5 library members have the same helper bytes.

The analyzer accepts the native x86 16-bit Protected Mode and Real Mode language IDs. Actual execution validation covers the supplied SimTower NE program in Protected Mode; Real Mode and other binaries have not been validated. Existing higher-priority function signatures are left unchanged.

The installed contract is:

| Analysis value | Native storage |
| --- | --- |
| Unsigned 16-bit byte count | `CX:2` |
| Source offset/selector record | Entry stack `+4`, four bytes |
| Destination offset/selector record | Entry stack `+8`, four bytes |
| Scalar return | No manufactured AX/DX result; analysis `void` |
| Argument cleanup | 8 bytes |
| Far return address / total extrapop | 4 bytes / 12 bytes |

`/LegacyToolchains/Borland/FarAddress16` contains a two-byte `offset` followed by a two-byte `selector`. It preserves argument storage; it is not a flat pointer, a recovered historical C declaration, or an implementation of selector resolution.

The prototype preserves the established saved/untouched registers. It declares `ES`, `CX`, `DF`, and arithmetic flags clobbered rather than incorrectly preserved. Clobber declarations do not calculate post-call values or express the helper's copy memory effects. There is no semantic copy callfixup in this increment.

## Build

Use JDK 21 and the Ghidra 12.1.4 installation. The validated build used Gradle 9.7.1; the selected Ghidra distribution declares a minimum Gradle version of 8.5. Set `JAVA_HOME` and `GHIDRA_INSTALL_DIR` to those local installations. From the enclosing Ghidra fork root, enter `extensions/ghidra-legacy-toolchains/` before running Gradle. The module-local `settings.gradle` establishes the independent build boundary and retains project name `ghidra-legacy-toolchains`; do not run the parent Ghidra build for this extension.

```bash
cd extensions/ghidra-legacy-toolchains
work=$(mktemp -d "$HOME/.cache/codex/ghidra-legacy-toolchains-build-XXXXXX")
mkdir -p "$work"/{tmp,home,config,cache,data,prefs/user,prefs/system}
export HOME="$work/home"
export TMPDIR="$work/tmp"
export XDG_CONFIG_HOME="$work/config"
export XDG_CACHE_HOME="$work/cache"
export XDG_DATA_HOME="$work/data"
export GRADLE_USER_HOME="$work/gradle-home"
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME -Djava.io.tmpdir=$TMPDIR -Djava.util.prefs.userRoot=$work/prefs/user -Djava.util.prefs.systemRoot=$work/prefs/system"
gradle --no-daemon --project-cache-dir "$work/project-cache" -PbuildOutputDir="$work/build" buildExtension
```

The native extension ZIP is written under `$work/build/dist/`. The build uses the selected installation's `support/buildExtension.gradle`; it does not vendor or rebuild Ghidra. No system installation is part of the build. `buildOutputDir` also redirects the native dependency-copy, source-archive, and ZIP outputs.

## Load without changing the Ghidra installation

Unpack the extension ZIP into a task-owned directory. The unpacked `ghidra-legacy-toolchains` directory contains `Module.manifest`, `extension.properties`, `data/`, `lib/`, and `ghidra_scripts/`.

For native headless analysis, supply the unpacked module through the supported JVM property:

```bash
export GHIDRA_HEADLESS_JAVA_OPTIONS="-Dghidra.external.modules=$module -Dapplication.settingsdir=$work/settings -Dapplication.cachedir=$work/cache -Duser.home=$work/home -Djava.io.tmpdir=$work/tmp"
```

Set `module` to the unpacked module directory and create the named private directories before launch. Also direct `HOME`, `TMPDIR`, XDG configuration/cache/data, and Java preferences to task-owned locations. This is the loading route validated here; GUI installation was not tested. Load the Java extension at process startup rather than assuming an already-running Ghidra instance will discover new classes.

Ghidra 12.1.4 rejects a project path with a dot-prefixed component. When actual project files are under a dot-prefixed cache directory, native analysis requires a task-owned nonhidden path alias to that exact directory. The historical validation used such an alias; it is not part of this module and is not needed for the Gradle build. The alias does not move original inputs or change their bytes.

Import NE inputs through `NeLoader`, keep native analysis enabled, and retain the analyzer's default enablement. Its priority follows Ghidra's generic segmented calling-convention pass; otherwise that pass overwrites the helper-specific convention based on `RETF` alone.

## Consume through the existing MCP

The extension adds no MCP endpoint. Load the same module in the Ghidra process served by the existing bridge. When using the MCP project's standalone Java headless entrypoint, include the extension's `lib/ghidra-legacy-toolchains.jar` on that process's classpath and set `ghidra.external.modules` to its unpacked module directory. Use the MCP project's own launcher/build procedure; this extension adds no second server or transport.

Use an explicit program project path on every operation. The validated sequence was:

1. Perform MCP `initialize` and `tools/list`; inspect `list_instances` to verify the exact private PID, socket, project, and program.

2. Call `run_analysis` with `program`. This initializes native analysis options and runs the installed analyzer. Immediately after opening a saved program, `list_analyzers` can be empty until options are initialized; an empty list alone does not prove the extension is missing.

3. Call `list_analyzers` and verify that `Borland F_SCOPY (qualified 16-bit)` is enabled.

4. Read the helper through `get_functions` with `fields` including `signature,parameters`. Read `FarAddress16` through `get_type_size` when its layout size is needed.

5. Call `save_program` after analysis changes and re-read the function to verify saved state.

For the qualified SimTower validation program, the observed helper address was `1000:3dc9`. That is an imported coordinate, not a universal address for other imports.

`ValidateFScopy.java` is a focused native integration check for this exact SimTower input and its three original caller sites. It is not a general-purpose script for arbitrary binaries. After native analysis, run it with one existing output-directory argument. It checks the production analyzer's result, rerun stability, storage/cleanup/preservation, and actual caller HighFunction inputs. The success marker is `F_SCOPY VALIDATION PASS`; headless exit status alone is insufficient because native analyzer/script errors can coexist with exit zero.

The existing `run_ghidra_script` MCP operation can run the installed script by absolute path with that output directory in `args`. It requires `GHIDRA_MCP_ALLOW_SCRIPTS=1` on the MCP server. The current bridge splits arguments on whitespace, so use an output path without spaces. This operation executed the same native assertions successfully in the integration run.

Keep these bridge boundaries explicit:

- An explicit `language` in the inspected MCP import implementation selects raw-binary import. Do not use it as a compiler-profile override while expecting NE loader semantics.

- `get_function_pcode` returns `HighFunction` operations, including in its `basic` mode. It is not an instruction-level `Instruction.getPcode()` export.

- The bridge searches UDS candidates before a TCP fallback and can remove stale sockets. A supplied URL alone does not establish target identity. The validated instance used task-private UDS state, verified absent outside candidates, and no TCP listener.

- Re-analysis is a Program mutation. The validation modified only its task-owned project; it did not change originals or an existing user's analysis project.

## Semantic limits

Do not treat the emitted C as segment-faithful reconstruction. The actual helper C dereferences the offset components without preserving the selector-dependent memory expressions. The separate TLINK writer probe likewise retains dynamic segment operations in HighFunction while the C view omits selector operands. Use native instruction/p-code evidence for those dependencies.

The TLINK probe showed that explicit analysis-only return storage can expose CF and additional register results, with a known near-return stack model. That experiment is not an automatically applied writer model, a recovered historical return type, or proof of caller propagation. See the [validation summary and historical report locator](validation.md) for the exact boundary.

This extension does not replace the original-byte reconstruction, compilation, and comparison cycle. Other runtime helpers, full memory-model support, precise copy side effects, whole-game recovery, and historical producer selection are outside this first increment.
