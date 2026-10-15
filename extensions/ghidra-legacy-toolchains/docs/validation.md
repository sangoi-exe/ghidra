# Validation evidence and boundaries

Status date: 2026-10-15 (`America/Sao_Paulo`). Active source owner: `extensions/ghidra-legacy-toolchains/` in this Ghidra fork. The supported build/loading procedure is in [usage](usage.md); historical first-increment evidence does not establish current integrated behavior.

## Current integration status

- **Matching runtime build:** source `b2314ae0710bace02cd110858a1a5459ae1a04c5` built through native `assembleAll`, including IP checks, with JDK25.0.2 and Gradle9.7.1. The included MZ correction passed four native tests and ordinary BCC2.0 import. No global installation or alternate loader is involved.

- **Automatic profiles:** all eight current profiles pass fresh ordinary automatic imports. The native imported-facts batch prevents its writes from triggering heuristic boundary/purge replacement. Saved-state checks retain qualified UNKNOWN cleanup and the actual TASM shared entry. VPRINTER's main1095 bytes and private scanner13/emitter-entry9/flush52 are separately represented;13 real private calls and the shared return are checked. No validator-side direct application hides missing activation.

- **Native decompiler:** the demonstrated call-argument regression is corrected. Focused native units pass8/8 and data assertions92/92. Actual fill-wrapper arguments are WORD LOADs through the evidenced SS/near-SP address domain; F_SCOPY caller assertions and the real TLINK writer pass. Five nonsegmented console controls remain byte-identical to baseline. This does not establish arbitrary call forms, general value forwarding or complete segmented-program semantics.

- **MCP integration remains blocked:** native bridge7.0.0 on this SDK passed initialization, exact private UDS/project identity, analysis of SCRANTIC/TLINK5.1/SIMTOWER, analyzer listing and all three saves. Each tested `get_functions` C request failed with `NoClassDefFoundError: ghidra/program/model/lang/SleighLanguageDescription`. `ServiceUtils.decoderOf` uses the old package and `getSlaFile()` accessor; this SDK supplies `ghidra.app.plugin.processors.sleigh.SleighLanguageDescription.getLanguageFile().getSlaFile()`. No MCP source was changed. Script execution, successful C-query consumption and completion review remain unverified/pending.

The main private evidence root is `/home/lucas/.cache/codex/legacy-toolchains-integrated-20261015-6O1kYi/`. The current SDK is `build-env/callarg-core-candidate/source/build/dist/ghidra_12.3_DEV`. Current automatic profile proof is in `integration/correction/`, with SimTower's final partition proof in `simtower-crt/function-boundaries/`. The root build at `delivery-x8JJo9/` passed; all28 packaged payload files matched the native-validated package byte-for-byte before this factual documentation update. Current MCP evidence and the saved private project are under `/home/lucas/.cache/codex/legacy-mcp-4wtVkp/`. A short task-scoped path avoids Unix socket path-length limits. Native project preparation used `-noanalysis`; MCP performed the actual analysis. The owned processes were then stopped. No normal-user project or installation changed.

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
