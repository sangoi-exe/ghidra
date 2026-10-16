# Safe legacy profiles and qualified RE candidates

Status: on-hold
Task mode: Doctrine
Lifecycle phase: Initial
Strategy epoch: 1
Plan kind: Feature / PRD Plan
Secondary kind: Bugfix / Regression Plan (five reproduced defects in existing extension owners)
Workspace: `/home/lucas/work/ghidra`
Task baseline: `3bb77e8dabb13abeb6f40f6a767e48b69d8725cd`

## Confirmed intent and current-user decisions

Deliver one integrated extension update that turns the four selected compiler/toolchain RE candidate groups into native Ghidra analysis available through the existing MCP. Correct the five reproduced preservation, qualification and pagination defects before adding those candidates. Keep the current extension owners and matching runtime. Preserve conflicting manual work and refuse operational contracts that the current code or context no longer supports. Original-image identity establishes provenance, not permission to overwrite an existing Program.

Authority is the current user in source session `01a13bb1-5597-7090-a92b-8426359342a8`. The following messages establish the decisions in source order; timestamps use `America/Sao_Paulo`:

- At `2026-10-15T20:27:25.860-03:00`, turn `01a141e4-5536-7222-9fb4-02abebc3ac43`, the user said `dei push, pode iniciar a implentação dos candidatos novos que fizerem sentido`. The preceding push was performed by the user. It does not authorize another push.
- The assistant's final paraphrase in that turn, source line 6933 at `2026-10-15T20:43:04.610-03:00`, proposed one delivery containing the whole `fmovmem`/`fmemmove` family and the qualified BCC 2.0, BCC 3.1 and BCC 4.5 additions, using existing extension/native owners, automatic original imports and actual MCP consumption. It excluded new core/MCP work, duplicate shifts, generic compiler heuristics and unmotivated tests.
- At `2026-10-15T20:54:31.939-03:00`, turn `01a141fd-25f4-7601-86af-4c1279a0bb7b`, source line 6940, the user answered `confirmo, mas também verifique esses itens:` and supplied the five findings plus `disassembly.txt` and `probes.txt`. This confirmed the four candidate groups and requested verification, not automatic adoption of every reviewer recommendation.
- The assistant reproduced all five defects and paraphrased the delta at source line 7133, `2026-10-15T21:11:06.930-03:00`: add the five corrections to the same delivery, before the candidates, in the current components without new core/loader changes; preserve conflicts/manual work, refuse contracts incompatible with current code/context and correct pagination arithmetic.
- At `2026-10-15T21:31:45.507-03:00`, turn `01a1421f-3a06-7462-abf4-1a9463bae320`, source line 7140, the user answered `sim, faça isso`. This confirms the delta and selects correction in the existing owners. The earlier MCP exclusion is narrowed only for the reproduced pagination defect and its direct followers.

No material route decision remains open before the Plan Gate. The normal post-Gate implementation checkpoint and the later exact Code Gate selection remain required. There is no Gate override, residual-risk acceptance, deployment authorization or external-write authorization. The preceding integrated-expansion plan remains complete; this is a new task, not a reopening of its completion verdict.

## User goal and primary behavior

Before this task, the extension recognizes exact original images and known helper bytes, but its shared operations can destroy overlapping manual data, reapply stale cleanup to patched code, clear a preserved function's flow override, and accept incompatible internal helper context. The copied MCP also overflows a valid pagination limit. The four new candidate groups are evidenced but not implemented.

After this task, native analysis applies the admitted facts only when the current Program supports them and preserves the demonstrated conflicting user work. Fresh qualified imports still receive the supported analysis. The new helpers/profiles expose qualified native functions, storage, tables, references and annotations through the unchanged MCP consumption route. Pagination returns the correct slice for the demonstrated maximum-int limit, with the existing response shape and offset/unbounded-limit behavior.

The primary `Feature / PRD Plan` fits the integrated user-visible analysis delivery. The secondary bugfix aspect is required by the five executed counterexamples. This is not a research-note deliverable, a replacement architecture, or a migration of existing user projects.

## Selected route and canonical owners

Modify the existing owners and their direct followers. `extensions/ghidra-legacy-toolchains/` remains the analysis extension; `extensions/ghidra-mcp/` remains the copied MCP consumer. Native Program, Listing, ProgramContext, FileBytes, relocation, function and compiler-spec APIs remain the foundations. No additional service, parser, ownership ledger, compatibility adapter or maintained proof framework is selected.

- `ToolchainProfile.Context.data` owns safe data application. Its decision must cover the full native modification footprint, including data units crossing either boundary, and preserve conflicting defined data and references. A missing high-priority symbol is not evidence that defined data is disposable. The existing equivalent-data rerun path remains supported.
- `ToolchainProfile.match` continues to identify original FileBytes. The shared function-application owner and direct profile consumers must separately qualify the current evidence needed for their operational contracts. Current bytes/context and legitimate native loader transformations must be distinguished; a blanket comparison of relocated memory to the original file is not the selected mechanism. Invalid current code is not repaired or silently overwritten by the profile.
- `SimTowerRuntimeProfile.formatting` must honor a preserved-function decision for its dependent VPRINTER flow edit. The demonstrated stale-analysis cleanup remains available only for an accepted, currently qualified application. Preserving the function must preserve its manual flow override too.
- `QualifiedRuntimeHelperAnalyzer` owns full instruction-context qualification for its live subclasses. Check effective context at each qualified instruction, using the existing per-instruction qualification pattern rather than introducing another recognition framework.
- `ServiceUtils.paged` and `pagedProgramItems` own overflow-safe slicing. Their direct consumers keep the existing request and response contracts; the existing `ServiceUtilsPagedTest` is the focused regression owner.

The user selected local corrections rather than leaving the reproduced defects in place while expanding their consumers. Global profile disablement was a temporary usage recommendation, not a selected product change. No other evidenced material architecture alternative requires selection before the first slice. Any changed internal owner contract propagates to its direct callers/tests/docs in the same task; obsolete paths are updated or deleted, not retained as aliases.

## Admitted candidate groups

1. Recognize the complete 128-byte `fmovmem`/`fmemmove` family. Qualify the 89-byte core, 39-byte wrapper and actual internal call relationship together. Apply their distinct argument order, caller-owned cleanup and return-storage contracts. The core's raw selector/offset direction decision is not unrestricted modern `memmove`; the wrapper's fresh destination DX:AX result is not a universal source-language or selector-validity guarantee. Retain the distinct existing 38-byte forward copier.
2. Extend `Bcc20Profile` with the complete selected operand/selector bodies and R335 zero-to-XOR facts, using the established exact-image mapping and qualified tables/references/annotations. Keep the shared SUB/XOR fragment shared. Numeric selectors/tags are not CPU register names, and the selected bodies do not initialize a complete record or establish unproved upstream requests.
3. Extend `Bcc31Profile` with the complete R320 lowering and R329/R333 record-preparation bodies, cleanup, literal tables and genuine references. Preserve fresh current-frame return ordering and the qualified zero-pair bypass. Do not infer pointer identity, purity, source type or actual unproved compiler-path traversal.
4. Extend `Bcc45Profile` with the selected RF26/RF30/RF31 complete bodies, cache query, formatter/IR distinctions, references and descriptive nine-byte pending-entry layout. Keep partial paths partial. The literal `ax,ax,` output and cached AL/FF query do not prove three allocated operands, 0039-to-003E rewriting or historical RF24 allocation. A descriptive dynamic-record layout does not authorize applying it at an unproved heap address.

## Evidence and observed failures

The fixed commit-screening report is `.sangoi/reports/2026-10-15-re-commit-frontier.md`. It records all 41 new commit subjects and the selected semantic evidence; it is not a complete audit of those commits. It is a subordinate evidence annex, not a Scope or status owner. Its original cutoffs and review tips remain fixed.

Readiness Recon then rechecked the selected live source owners at Johnny `0eea64a586e1d427728e79fae8af2882f02e7b45` and SimTower `49e114314c8cde1cc0554505eb46c11617678d86`. Johnny's selected BCC owners were unchanged from the report tip. SimTower's three selected BCC 4.5 owners were also unchanged through `11953a40830c538e728fd45060467540aab0f309`. These are finite evidence frontiers, not permission to absorb continuing RE automatically. Named retained original/tool bytes and proof artifacts substantiate the candidate extents, entries and bindings; recheck each dispatched entry's anchors before editing.

Native pre-change evidence is `/home/lucas/.cache/codex/legacy-findings-verification-bJUZ9N/native-findings.log`, produced on the task baseline with the matching 12.3 SDK. Nine observation scenarios completed, including controls:

- A 74-byte manual structure beginning two bytes before a requested 70-byte data region was replaced; its USER_DEFINED symbol survived while its outgoing reference count fell from 1 to 0. A conflicting unsymbolized structure was also replaced. A high-priority symbol inside the requested range correctly prevented mutation.
- On a fresh native SimTower import, current FILE 0x4699 was changed from 0x0c to 0 after clearing/redecoding the terminal instruction. The same original still qualified. The production analyzer returned true and changed purge 0 back to 12 while the instruction remained `RET 0`.
- USER_DEFINED VPRINTER at FILE 0x420a retained its body/signature, but the production analyzer changed FILE 0x4222 from CALL_RETURN to NONE and effective p-code from CALL/RETURN to BRANCH.
- A native protected-mode Program containing the complete predecoded F_SCOPY bytes retained incorrect internal opsize or addrsize at entry + 0x0f. Native p-code changed to a four-byte move or 32-bit addressing, but the production analyzer still applied the 16-bit contract. The normal-context control was accepted.
- Both actual `ServiceUtils` methods threw `IllegalArgumentException` for two items, offset 1 and `Integer.MAX_VALUE`. Static caller/bridge inspection established a reachable request path; HTTP/stdio was not executed for this counterexample. Local upstream `cf8b12db27eb139b28b90eaa3488306da910d759` contains the same arithmetic.

These are reproduced defects, not hypothetical hardening requirements. No known-good implementation of the five adverse cases is established; the unchanged fresh-import and inside-symbol controls are the available comparisons. The earlier passing happy-path validation is not contrary evidence. The disposable probe's successful exit means the counterexamples were observed, not that corrections passed. Source-stdin launch logged an unrelated Log4j `/dev/log` discovery error before completing native initialization and the scenarios; an earlier JShell initialization failed and was closed. No original executable was run and no existing user project was edited.

## Scope, exclusions and authority

Product writes are confined to the two extensions, their direct tests/native validation scripts, generated packages and active product documentation. The root owns this plan, the report's factual disposition updates, the required task log and changelog. Existing Ghidra core, loader, processor and segmented-C implementation remain read-only inputs. Shared-owner changes require checking their current live profile/helper consumers, not a speculative matrix of future inputs.

The source RE repositories, their sessions, original binaries and retained proof inputs remain read-only. Fresh task-owned imports, fixture Programs, builds and private MCP processes may be used for validation under `/home/lucas/.cache/codex/`. Do not package proprietary inputs or mutate existing analysis projects, global installations/configuration or other sessions' resources. No push, external upload, new worktree, old-repository deletion or original game/compiler/linker execution is authorized.

Excluded: generic compiler/version detection, optimizer emulation, new loader/core or protocol changes, duplicate shift implementations, complete NB02 import, game-specific resource support, source-language recovery, runtime selector resolution and new tests justified only by emitted-byte equality. A new material owner, unsupported loader transformation or required Scope expansion returns to the user instead of adding a fallback.

## Acceptance and immediate proof

1. The overlapping/unsymbolized manual-data counterexamples preserve the existing type, full extent and references; the inside-symbol and equivalent-data controls remain correct. Conflicts are visible rather than silently destroyed or treated as successful application.
2. The patched-current-code case cannot silently reacquire the original purge. Qualification still accepts the legitimate native loaded originals, including their evidenced relocations. A preserved VPRINTER retains its manual flow override and effective flow.
3. The native internal-context counterexamples do not receive the incompatible helper contract. The normal helper and current live consumers of the changed shared qualification owner retain their established behavior.
4. Both pagination methods return only the second item for the reproduced limit, preserve existing response metadata and retain current offset/unbounded-limit semantics. The current direct test owner protects this regression; an actual MCP request confirms the relevant boundary after integration.
5. Fresh automatic imports apply all four admitted candidate groups with the evidenced bodies, cleanup, types, tables/references and qualifications. Existing profile/helper consumers of changed shared owners remain supported or expose an actual conflict without overwriting it. Native instruction/p-code and relevant caller observations decide the helper contracts; names or comments alone are not proof.
6. Both extensions build/package against the existing matching 12.3 SDK and the private existing MCP route can consume the resulting native analysis. Tests/docs distinguish direct invocation, automatic import and actual transport evidence. No unchanged decompiler suite is rerun merely for ceremony.
7. One committed integrated candidate receives the newly selected Code Gate, followed by truthful task-log/changelog bookkeeping and final Git inspection. Unverified surfaces remain explicit; previous completed-task review/validation is not relabeled as proof of this update.

The first directly verifiable slice is the shared data-preservation correction and its existing native validation boundary: preserve the demonstrated crossing/unsymbolized units and references, retain the positive controls, then apply the supported data on a fresh qualified import. This sizes execution, not the final architecture. Current-byte qualification and dependent flow preservation follow before adding new profile facts; helper-context and MCP pagination corrections are separate stable owner partitions. Candidate additions follow the corrected shared boundaries. Final native automatic-import/MCP consumption closes the integrated result.

Use the already-built matching SDK at `/home/lucas/.cache/codex/segmented-call-remediation-vb7J1D/implementation/source/build/dist/ghidra_12.3_DEV`, JDK 25 at `/home/lucas/.cache/codex/legacy-toolchains-integrated-20261015-6O1kYi/build-env/tools/jdk-25.0.2`, and existing Gradle 9.7.1. New build/import/probe output gets a fresh task cache. Changing extension code requires a fresh process loading the new package for integration proof; it does not authorize replacing the user's normal installation.

## Execution projection and continuity

The root retains strategy, semantic integration, Git and final proof. Bounded Workers implement the established owner corrections and candidate additions; exact write footprints and validation-read dependencies are established before dispatch. No concurrent writer may change a shared validation dependency. There is no subordinate microtask annex; the root's transient Microtask Program is the execution projection, not another intent authority.

Current Plan Gate: local `Senior Plan Auditor / Intent contract audit` on `/root/safe_legacy_candidates_plan_audit` returned `PROCEED`, with no material findings, for this complete epoch1 Intent Contract. The reviewer accounted for every required contract field, corroborated the current-user chronology and native before-state evidence, and reported no required unreviewed or evidence-blocked field. No tests were rerun and no implementation was reviewed. Root applied the sole registered Doctrine / Initial / PROCEED transition: this plan is on-hold in Initial pending later current-user implementation authorization. No implementation has started.

Current Code Gate: not selected for this task. Previous local selections expired with their terminal outcomes. Select one of local Senior Code Reviewer, ChatGPT Web Extra High or ChatGPT Web Pro for the eventual committed candidate; no selection is inferred now.

Blocker: required later current-user implementation authorization after the completed Plan Gate.
Next high-level action: obtain that authorization, activate Implementation and dispatch the first correction slice. The confirmed Scope and selected route remain closed; no new paraphrase or Plan Gate is required unless material evidence changes them.
