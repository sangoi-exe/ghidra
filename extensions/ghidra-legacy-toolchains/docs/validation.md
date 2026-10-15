# Validation evidence and boundaries

Status date: 2026-10-15 (`America/Sao_Paulo`). Active source owner: `extensions/ghidra-legacy-toolchains/` in this Ghidra fork. The supported build/loading procedure is in [usage](usage.md); historical first-increment evidence does not establish current integrated behavior.

## Current integration status

- **Matching runtime build:** source `b2314ae0710bace02cd110858a1a5459ae1a04c5` built through native `assembleAll`, including IP checks, with JDK25.0.2 and Gradle9.7.1. The included MZ correction passed four native tests and ordinary BCC2.0 import. No global installation or alternate loader is involved.

- **Automatic profiles:** all eight current profiles pass fresh ordinary automatic imports. The native imported-facts batch prevents its writes from triggering heuristic boundary/purge replacement. Saved-state checks retain qualified UNKNOWN cleanup and the actual TASM shared entry. VPRINTER's main1095 bytes and private scanner13/emitter-entry9/flush52 are separately represented;13 real private calls and the shared return are checked. No validator-side direct application hides missing activation.

- **Native decompiler:** the demonstrated call-argument regression is corrected. Focused native units pass8/8 and data assertions92/92. Actual fill-wrapper arguments are WORD LOADs through the evidenced SS/near-SP address domain; F_SCOPY caller assertions and the real TLINK writer pass. Five nonsegmented console controls remain byte-identical to baseline. This does not establish arbitrary call forms, general value forwarding or complete segmented-program semantics.

- **MCP integration:** the sibling `extensions/ghidra-mcp/` 7.0.0 source port now builds independently against the matching 12.3 SDK/JDK 25 and resolves the earlier SLEIGH API failure. The copied stdio Python bridge connected to one exact owned Java headless UDS instance with TCP disabled. Actual SCRANTIC/TLINK 5.1/SimTower analysis and all three saves passed. The exact previously failing `get_functions` argument sets returned nonempty C for F_PCMP (33 bytes), memset (29), the TLINK writer (150), F_SCOPY (28) and VPRINTER (1095); writer C retains 25 `segmentop` expressions. This is bounded consumption proof, not broader native semantic correctness or complete endpoint coverage. MCP `run_ghidra_script`, GUI installation/startup and completion review remain unverified/pending.

The main private evidence root is `/home/lucas/.cache/codex/legacy-toolchains-integrated-20261015-6O1kYi/`. The current SDK is `build-env/callarg-core-candidate/source/build/dist/ghidra_12.3_DEV`. Current automatic profile proof is in `integration/correction/`, with SimTower's final partition proof in `simtower-crt/function-boundaries/`. The root build at `delivery-x8JJo9/` passed; all28 packaged payload files matched the native-validated package byte-for-byte before this factual documentation update. Current MCP port evidence and the saved private project are under `/home/lucas/.cache/codex/ghidra-mcp-port-ZD5QV1/`: `native-prep/headless.log` records fresh `-noanalysis` imports, `results/query-summary.json` summarizes C retrieval for the five functions, and `results/*-analysis.json` / `*-save.json` record actual MCP analysis and saves. Before/after project/file observations retain the same three non-versioned Programs in `LegacyMcpPort20261015`. The owned Java/bridge processes were stopped after saving; the private project/logs remain. No normal-user project, installation or global MCP configuration changed. Server logs contain existing Ghidra/Unsafe/content-class warnings; warning-free execution is not claimed.

The MCP source port retains upstream commit `cf8b12db27eb139b28b90eaa3488306da910d759`, layout and licenses, with localized adaptations and CRLF-to-LF normalization under the parent repository's existing Git attributes. Python runtime/protocol content is preserved apart from that line-ending normalization. `worker/logs/build-decoder-03.log` records the native extension build; focused decoder and datatype-struct tests passed 7/7 and 5/5. The expanded Java invocation (`worker/logs/java-port-regressions-04.log`) passed 72 tests but failed five ProjectLocator fixtures because of the physical `.cache` path. A separate directory-FD temp-path rerun passed only those five fixtures, with zero failures/errors/skips (`final-java/build/test-results/test/TEST-com.xebyte.core.ProjectPathsGhidraTest.xml`); this is not one clean 77/77 invocation. Python units passed 1095 with nine platform skips and one upstream Starlette deprecation warning (`worker/logs/python-unit-02.log`). Validation used Gradle 9.7.1; the retained wrapper is 9.8.0. Full Java-suite coverage, Maven packaging, debugger/BSim and all endpoints remain untested.

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
