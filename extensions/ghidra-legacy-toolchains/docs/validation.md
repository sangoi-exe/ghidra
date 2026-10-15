# Validation evidence and boundaries

Status date: 2026-10-15 (`America/Sao_Paulo`). Active source owner: `extensions/ghidra-legacy-toolchains/` in this Ghidra fork. The supported build/loading procedure is in [usage](usage.md); historical first-increment evidence does not establish current integrated behavior.

## Current integration status

- **Matching runtime build:** core checkpoint `45dbf35174fc1ef00ab4ba9c9ace64559792c6ef` built successfully through normal native `assembleAll`, including IP checks, with JDK 25.0.2 and Gradle 9.7.1: 650 actionable tasks, 405 executed and 245 up-to-date, with ordinary Gradle deprecation warnings. SDK/source/runtime equality checks identify the rebuilt native executable, compiler specification and Java classes. No global installation or alternate loader is involved.

- **Automatic profile baseline:** the earlier 2026-10-15 `b2314ae0710bace02cd110858a1a5459ae1a04c5` SDK/profile validation established all eight ordinary automatic imports. Unchanged profile sources/results are reused, not eight profile runs repeated on the latest SDK. The native imported-facts batch prevents its writes from triggering heuristic boundary/purge replacement. Saved-state checks retain qualified UNKNOWN cleanup and the actual TASM shared entry. VPRINTER's main1095 bytes and private scanner13/emitter-entry9/flush52 are separately represented;13 real private calls and the shared return are checked. No validator-side direct application hides missing activation. The earlier included MZ correction passed four native tests and ordinary BCC 2.0 import.

- **Native decompiler:** optional compiler `<stackpointer segmentregister="SS">` metadata now identifies the stack selector; real calls read its current register value while synthetic stack bookkeeping stays offset-only. The binding no longer depends on a CALL-address STORE or inference from a generic SegmentOp, and adds no generic Spacebase API or fallback. The original real JMP/CALL_RETURN replay emits `jump_target(*(uint2 *)segmentop(unaff_SS,&value))` without a same-address STORE. Full native units pass 209/209, focused data assertions 92/92, and the original replay passes. Java/native integration passes two tests with zero failures/errors/skips; copy/equivalence/re-encoding and native registration cover Protected/Real/SMM compiler metadata, but actual CALL_RETURN decompilation is tested only in Protected Mode. This does not establish general Real Mode/SMM execution, arbitrary call forms, general value forwarding or complete segmented-program semantics.

- **MCP integration:** the unchanged sibling `extensions/ghidra-mcp/` 7.0.0 source port again passed actual integration on the corrected matching 12.3 SDK/JDK 25. The stdio Python bridge connected to one exact owned Java headless UDS instance with TCP disabled. Fresh SCRANTIC/TLINK 5.1/SimTower analysis and all three saves passed. Three exact `get_functions` queries returned nonempty C for F_PCMP (33 bytes), memset (29), the TLINK writer (150), F_SCOPY (28) and VPRINTER (1095). All five C strings are byte-identical to the prior successful port responses; writer C retains 25 `segmentop` expressions. This is bounded consumption proof, not broader native semantic correctness or complete endpoint coverage. MCP `run_ghidra_script` and GUI installation/startup remain unverified.

The current native evidence root is `/home/lucas/.cache/codex/segmented-call-remediation-vb7J1D/implementation/`; its SDK is `source/build/dist/ghidra_12.3_DEV`. `logs/native-{unit,data,r1}-sdk-final.log`, `logs/java-integration-final-results.xml` and `logs/java-native-execve-final.log` record the native tests, real Java/native execution and rebuilt executable use. `logs/assemble-all-clean.log`, `logs/sdk-byte-comparison-final.log` and `logs/source-byte-comparison-final.log` identify the complete matching distribution and source/runtime equality. Earlier profile/helper evidence remains under `/home/lucas/.cache/codex/legacy-toolchains-integrated-20261015-6O1kYi/`, including `integration/correction/` and `simtower-crt/function-boundaries/`; the table below refers to that baseline evidence root, not newly repeated runs.

Current MCP evidence and the saved private project are under `/home/lucas/.cache/codex/ss-mcp-njI10o/`. `results/query-summary.json` summarizes the five functions; `results/*-analysis.json` and `*-save.json` record actual MCP analysis and saves. Before/after project/file observations retain the same three non-versioned Programs in `StackSelectorMcp20261015`. All observed owned Python/bridge/Java/demangler processes exited and the socket was removed (`results/shutdown.json`); private project/evidence remain. No normal-user project, installation or global MCP configuration changed. `logs/server.log` contains existing Unsafe/DataTypeArchive warnings and slow-analysis notices; warning-free execution is not claimed.

The MCP source port retains upstream commit `cf8b12db27eb139b28b90eaa3488306da910d759`, layout and licenses, with localized adaptations and CRLF-to-LF normalization under the parent repository's existing Git attributes. Python runtime/protocol content is preserved apart from that line-ending normalization. Earlier source-unchanged port evidence is retained under `/home/lucas/.cache/codex/ghidra-mcp-port-ZD5QV1/`: focused decoder and datatype-struct tests passed 7/7 and 5/5 (`worker/logs/build-decoder-03.log`). The expanded Java invocation (`worker/logs/java-port-regressions-04.log`) passed 72 tests but failed five ProjectLocator fixtures because of the physical `.cache` path. A separate directory-FD temp-path rerun passed only those five fixtures, with zero failures/errors/skips (`final-java/build/test-results/test/TEST-com.xebyte.core.ProjectPathsGhidraTest.xml`); this is not one clean 77/77 invocation. Python units passed 1095 with nine platform skips and one upstream Starlette deprecation warning (`worker/logs/python-unit-02.log`). These port unit checks were not rerun for the latest SDK correction. Validation used Gradle 9.7.1; the retained wrapper is 9.8.0. Full Java-suite coverage, Maven packaging, debugger/BSim, cross-platform native execution and all endpoints remain untested.

## Bounded native observations

| Surface | Observed evidence and limit | Evidence directories under the private root |
| --- | --- | --- |
| BCC 2.0/3.1/4.5, TASM 3.1, TLINK 4.01/5.1 | Exact original FileBytes, selected native mapping/layout/enum/function/reference outcomes, rerun behavior and user-annotation preservation. BCC 2.0 overlays remain static projections; partial layouts and state-dependent conclusions remain qualified. | `bcc20/`, `bcc31/`, `profiles/`, `tasm31/`, `tlink-profiles/` |
| SCRANTIC/SimTower runtime profiles | Selected complete extents, stored bindings and data correspondence on the named supplied originals; not full ABI, transitive servicing or historical producer proof. | `scrantic-crt/`, `simtower-crt/` |
| F_SCOPY and 38-byte far copy | Native frame/storage assertions and actual NE caller inputs; F_SCOPY's three caller counts were16/8/8. The far copier has caller-owned ten-byte arguments and a DX:AX offset-selector record result. F_SCOPY was also revalidated on the corrected core. | `far-copy/`, `core/segmented-call-correction/fscopy-run-1/` |
| F_PCMP | Complete 33-byte body, normalized nine-byte ZF/AX/DX/BX/CX analysis storage and an actual NE7 caller's CALL-to-CBRANCH ZF dependency. No modern pointer comparison ABI is inferred. | `pcmp/` |
| setmem/memset | Complete40/29-byte bodies, WORD storage/results, real PUSH CS/near CALL/RETF frames, six-byte caller cleanup and actual selector-qualified call arguments. No host-pointer or exact fill-effect contract. | `fill/`, `core/segmented-call-correction/m10-run-1/` |
| Word-pair shifts | Three non-overlapping far cores and actual labeled near adapters; seven original far callers observed. Finite-word mathematical qualification covers CL 0..31, not arbitrary runtime CPU execution. | `word-shifts/` |
| NE relocation provenance | Selected actual applications from SCRANTIC/Johnny, SimTower and WAVMIX; original/current fields, unique operand masks, chain/application distinction, repeatable comments and unchanged native references. Existing native unsupported/additive cases remain limitations. | `ne-provenance/` |
| NB02 | Three actual samples passed complete initial/footer bytes, retained-end distance arithmetic, original FileBytes and native mapping checks. All observed records were unmapped: no invented memory was created. The mapped-record comment branch remains untested. | `nb02/` |

Native process exit zero is insufficient: inspect explicit validator PASS markers, analyzer/script errors and successful native import/save messages. A timeout, probe-only run, missing output or unsaved Program does not establish the corresponding claim. These are static original-byte/native-analysis checks, not execution of the original legacy programs.

## Focused native checks

Use a fresh matching runtime, rebuilt extension ZIP and private environment from [usage](usage.md#load-in-a-private-native-process). Each script targets selected evidenced originals, not arbitrary similarly named binaries. Supply absolute original/output paths and create the output directory first. For example, after setting `original` to the qualified BCC 3.1 image:

```bash
project_parent="$work/projects"
output="$work/validation/bcc31"
mkdir -p "$project_parent" "$output"
exec 9<"$project_parent"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "/proc/$$/fd/9" legacy-bcc31 \
  -import "$original" \
  -scriptPath "$module/ghidra_scripts" \
  -postScript ValidateBcc31Profile.java "$original" "$output" automatic \
  -log "$work/headless.log" -scriptlog "$work/scripts.log"
exec 9<&-
```

Leave native analysis enabled. `automatic` requires the profile to be present before the script reruns it; `direct` explicitly applies the profile and does not prove automatic activation. The BCC 4.5 validator has no mode argument and requires prior automatic application. Preserve the logs and inspect the actual script result and import/save records, not just the shell status.

All script paths below are relative to the module's existing `ghidra_scripts/` directory. `original` means the exact named input; `output` means an existing private directory. Separate outputs prevent one validator's artifacts from obscuring another's.

| Script | Positional arguments | Success marker |
| --- | --- | --- |
| `ValidateBcc20Profile.java` | `original output direct\|automatic` | `BCC20 PROFILE VALIDATION PASS` |
| `ValidateBcc31Profile.java` | `original output direct\|automatic` | `BCC31 PROFILE VALIDATION PASS` |
| `ValidateBcc45Profile.java` | `original output` | `BCC45 PROFILE VALIDATION PASS` |
| `ValidateTasm31Profile.java` | `original output direct\|automatic` | `TASM31 PROFILE VALIDATION PASS` |
| `ValidateTlinkProfiles.java` | `original output direct\|automatic runtime-label` | `TLINK PROFILE VALIDATION PASS` |
| `ValidateScranticRuntimeProfile.java` | `original output direct\|automatic` | `SCRANTIC RUNTIME PROFILE VALIDATION PASS` |
| `ValidateSimTowerRuntimeProfile.java` | `original output direct\|automatic` | `SIMTOWER RUNTIME PROFILE VALIDATION PASS` |
| `ValidateFScopy.java` | `output` | `F_SCOPY VALIDATION PASS` |
| `ValidateFarCopy.java` | `output` | `FAR COPY VALIDATION PASS` |
| `ValidateFarPointerCompare.java` | `output` | `FAR POINTER COMPARE VALIDATION PASS` |
| `ValidateMemoryFill.java` | `output` | `MEMORY FILL VALIDATION PASS` |
| `ValidateWordPairShifts.java` | `output` | `WORD PAIR SHIFTS VALIDATION PASS` |
| `ValidateNeRelocationProvenance.java` | `output johnny\|simtower\|wavmix` | `NE PROVENANCE VALIDATION PASS` |
| `ValidateNb02Structure.java` | `original output initial-offset footer-offset distance` | `NB02 STRUCTURE VALIDATION PASS` |

`runtime-label` records the selected TLINK runtime identity; it does not select an implementation. NB02 offsets/distance accept Java `Long.decode` forms, including `0x` hexadecimal, and must come from the selected actual original. The optional NE provenance `probe` argument stops after observation and emits `NE PROVENANCE PROBE COMPLETE`, not the full validation PASS. Through MCP, invoke these same scripts using the existing [script operation and argument restrictions](usage.md#consume-through-the-existing-mcp); do not add a second transport or infer raw p-code from `get_function_pcode`.

## Historical baseline and exclusions

The original F_SCOPY-only increment used Ghidra 12.1.4 PUBLIC/JDK 21 and actual MCP 7.0.0 execution. Its retained report is `/home/lucas/work/ghidra-legacy-toolchains/.sangoi/reports/2026-10-14-first-increment-validation.md` at historical source commit `70476eee3a31f966e28943db700333d23475d585`. That repository/report is historical evidence, not another active source owner or the present build procedure. In particular, its no-core-patch claim, omitted-selector C view and external-module launch recipe do not describe the current integrated fork.

No GUI installation, full arbitrary-binary corpus, general Real Mode execution, original compiler/linker/game execution, complete debug symbol/type import, whole-game recovery, host-compilable reconstructed C or remote publication is established. See [semantic limits](usage.md#semantic-limits) for the analysis contract; successful packaging alone establishes none of these behaviors.
