# Integrated legacy-toolchain analysis extension

Status: on-hold
Task mode: Doctrine
Lifecycle phase: Strategy reset
Strategy epoch: 2
Plan kind: Feature / PRD Plan
Secondary kind: Architecture / RFC Plan (the user-authorized decompiler owner boundary only)
Workspace: `/home/lucas/work/ghidra`

## Confirmed intent and current-user authority

The user wants demonstrated compiler/toolchain reverse-engineering knowledge from Johnny Castaway and SimTower to become executable Ghidra analysis rather than knowledge available only in Markdown. The result is one integrated expansion of the existing `extensions/ghidra-legacy-toolchains/` module and a focused correction of this fork's decompiler so emitted C retains material segmented-memory dependencies. The existing MCP consumes the resulting native Program/decompiler output. Keep necessary upstream changes concentrated rather than preserving incorrect core behavior solely to avoid a diff.

Current-user decisions in this thread's source order:

- After the seven-lane read-only reconnaissance, the user said `faça a sua recomendação, mas pode ampliar o escopo pra fazer tudo de uma vez em vez de dividir em várias partes`.

- The assistant paraphrased one delivery covering qualified BCC 2.0/3.1/4.5, TASM 3.1 and TLINK 4.01/5.1 profiles; evidence-backed runtime helpers; transformed calls, special returns, inline data and NE references; and structural NB02 recognition. The paraphrase retained the current extension/native mechanisms, preserved original Ghidra files, and explicitly excluded segmented-C printer changes, a complete NB02 debug importer and Johnny-specific resource formats. Worker partitioning was an execution detail, not separate product deliveries.

- The user answered `confirmo, mas porque deixou de fora essas 3 alterações, não são boas?`. This confirms that paraphrase. The accompanying question requests the reasons for the three exclusions; it does not select their implementation. The assistant explained their respective core/decompiler boundary, incomplete debug-format evidence and separate game-resource domain.

- The user then explicitly added `vamos incluir no escopo os ajustes no C segmentado fiel`, explaining its importance for decompilation. The assistant paraphrased the delta: preserve selector, offset and DS/ES/SS dependencies in emitted C expressions, permit necessary concentrated decompiler-core changes, and validate against the demonstrated instructions/p-code beginning with the TLINK writer, without inventing selector resolution or historical C. Full NB02 import and Johnny resources remained excluded.

- The user's latest `sim, confirmo` explicitly confirms that delta, including permission to change the decompiler core when needed. This expands the Scope and changes the canonical-owner boundary; strategy epoch 2 replaces the unreviewed extension-only draft. No prior Plan Gate or implementation occurred for that draft.

The completed placement task and its local review remain historical baseline evidence, not execution authority for this feature. The confirmed current intent authorizes the current Plan Gate through its result. No post-Plan-Gate implementation authorization, new completion Code Gate choice, external push, global installation or original-tool execution has been supplied for this feature.

## User goal and before/after behavior

Before: fork baseline `357c77c44762013e4fbbf8c71f477709c086d99a` contains one native exact-body F_SCOPY analyzer, its per-Program prototype, a focused native integration script, and standalone installed-Ghidra packaging. Historical native proof used Ghidra 12.1.4 PUBLIC, JDK 21 and Gradle 9.7.1. The actual fork source is 12.3 DEV and requires Java 25. Current `PrintC::opSegmentOp` omits the selector; the retained 12.1.4 TLINK writer experiment demonstrates the corresponding selector-dependent C loss. Only pre-existing untracked `.refs/` was present at intake.

After: the same extension applies qualified tool-image knowledge and helper contracts to native Ghidra Programs, adds the selected structural/call/reference analyses, and exposes their results through existing Program data consumed by the MCP. The matched fork decompiler preserves the actual selector/offset dependencies in the admitted segmented-memory cases rather than presenting misleading flat-pointer expressions. The user receives one integrated, validated delivery, not a succession of reduced feature releases. Descriptive analysis names, partial structures and explicit analysis expressions remain distinct from historical identifiers/types, resolved selectors or recovered historical C.

`Feature / PRD Plan` fits because the primary result is integrated user-visible analysis functionality, not a research-note deliverable. The secondary architecture aspect records the explicitly authorized change from extension-only ownership to the natural decompiler owner and its direct followers; it does not import another plan/checklist or select a broad upstream redesign.

## Selected route and canonical owners

Keep the independent extension inside this fork. Use native analyzers, file-backed memory/address mapping, datatypes, symbols, references, function models and per-Program specification extensions. The current Java analyzer, XML prototype, native scripts, build files and module docs are the seed owners. Cohesive sibling responsibilities may be added inside the module when current repeated profile/helper work justifies them; no parallel server, transport, generic proof framework or separate repository is selected.

Ghidra's native NE/MZ loaders and processor semantics remain the input foundations, not replacement targets. The existing C decompiler owns the segmented-expression correction, including directly implicated address/value rendering, typing or stack/spacebase transformations needed to preserve the requested meaning. The existing MCP remains an unchanged consumer. It already exposes analyzed functions/types/references and can invoke installed native scripts under its existing configuration. Its `get_function_pcode`, including `basic`, is HighFunction-derived, not an independent raw-instruction oracle.

Two distinctions govern the resulting system:

- Exact-tool profiles apply established facts to the identified compiler/assembler/linker image. A conditional callback installation can support table labels and possible references without proving a particular historical compiler invocation.

- Helper and pattern recognition on other binaries requires the evidenced bytes, context, relationships and contracts. A match does not elect a historical compiler release, recover historical source, import one game's semantics into another, or justify an unrestricted modern C prototype.

Existing native loaders already apply the selected NE relocation forms, and the x86 language already models PUSH CS, near CALL and RETF. Extend their useful analysis results instead of replacing those owners. Correct segment-dependent C at its actual owner chain rather than adding comments, postprocessing printed text, or creating another print language/server/runtime. A separate print language is technically available but adds selection/follower obligations without an evidenced need for the admitted result. The full NB02 importer and game-resource features remain outside the selected route.

Native analysis already represents SEGMENTOP as an address construction. Prefer preserving its selector/offset expression together with the existing typed access semantics. Explicit read/write intrinsic rendering is a technical alternative if current address/value printing cannot faithfully represent an admitted case, not a new selector-resolution service. Exact analysis notation remains an implementation choice within the requested semantic result; do not claim compilable host-pointer semantics or invent an external runtime API.

## Admitted capability envelope

### Exact tool-image profiles

Cover the demonstrated profile groups for BCC 2.0, BCC 3.1, BCC 4.5, TASM 3.1, TLINK 4.01 and TLINK 5.1. These include qualified function/data boundaries, partial record/descriptor layouts, known numeric enums, option and callback tables, real typed references, state-field annotations and supported function/register/stack contracts. Preserve version-specific differences such as near callbacks versus FAR tables, separate parallel arrays versus interleaved records, and distinct instruction/node/category domains.

Coordinates are artifact-qualified. NE table ordinals, loader-assigned segment addresses, MZ paragraphs, file offsets, overlay table identifiers and runtime selectors are not interchangeable. Native original FileBytes and established body/stub/fixup relationships supply the mapping basis. Newly demonstrated input issue: stock MZ loading retains the complete BCC2.0 file but does not map its appended FBOV bodies. The exact-image profile therefore includes projecting its qualified recorded regions into native file-backed analysis memory and preserving the recorded relationships; this does not select a generic FBOV loader, dynamic overlay execution or a new general binary parser. If correct profile behavior needs one of those broader responsibilities, stop that dependent frontier for a user decision rather than silently substituting it.

### Runtime helpers and generated-call structures

Retain the established F_SCOPY result and extend the demonstrated families: the 38-byte far copier, F_PCMP, setmem/memset, word-pair shifts, and qualified LSEEK/heap/startup/formatting correspondence. Implement recognition and the contracts actually established for each family; unresolved subordinate effects and historical spelling remain explicit. A complete body/member relation is not permission to substitute modern library semantics.

F_PCMP must not become AX-bool or raw-pair equality. Flag/register-result retention and relevant caller consumption require native validation before applying a stronger decompiler-visible contract. Existing native experiments demonstrated CF and combined ES/CX/DX/CF body outputs, not this comparator's caller behavior. Pattern analysis includes assembler/linker far-compatible call forms, returned-flag helpers, consumed-return/inline-data forms, and the demonstrated branch/switch/zero-test shapes as qualified observations rather than universal compiler classifiers.

### NE reference provenance and NB02 structure

Enrich native relocation/instruction relationships where the demonstrated cases require it: patched operand ownership, preserved offset/selector components, additive versus chained interpretation, conditional targets and code/data/caller qualification. A relocation site is not automatically a CALL, loaded selector or proved whole-program edge. Use native retained relocation/original-byte information rather than duplicate NE loading.

Recognize the demonstrated NB02 initial-record and terminal-footer structures and their bounded file-position relationships. Do not infer a complete debug directory, recover symbols/types, or declare debug information removed merely from these markers.

### Segmented-memory C expressions

Preserve material selector, offset and DS/ES/SS dependencies in the generated expressions for the real corpus, starting with the TLINK5.1 writer and F_SCOPY. Actual access width, address-versus-value meaning and the proved instruction/p-code relationships must survive. A register name in a comment or declaration is not proof that a memory expression retained the dependency.

The natural chain includes `ActionSegmentize`, `TypeOpSegment`, C SEGMENTOP/LOAD/STORE/array-member printing, and the directly implicated stack/spacebase rules. Current `RuleLoadVarnode::checkSpacebase` explicitly ignores SEGMENTOP's base before LOAD/STORE-to-COPY normalization; this can remove information before the printer. Conversely, `Funcdata::createStackRef` synthesizes zero-base segment operations. Preserve real dependencies without inventing selector reads for synthetic stack references. Legitimate constant resolution or stack abstractions may remain only when they do not discard the required dependency; numerical selector resolution, live descriptor tables and runtime loading history are not inferred.

The proof obligation is the confirmed semantic result, not blanket disabling of optimization or a cosmetic one-method patch. Current native execution will decide the demonstrated SS and load/store rendering paths. An observed need for a new language/processor, external runtime or general selector service returns to the user; ordinary corrections within this selected decompiler owner chain do not require another strategy choice.

## Evidence frontier and authority boundaries

The read-only discovery screened all 1,136 Johnny subjects through `5e6c9dbe88e0f5cd9d48e9056415069b912450a0` and all 310 SimTower subjects through `e90bb42a20d333a6fa8b3c35f2ca330a213589c5`; selected diffs, canonical producers, direct tests and retained observations were substantively inspected. Subject screening is not a semantic audit of every commit. Johnny's later `5c3a67c6d2e0b422ed115be7653c5b9ec7b842c8` adds the observed R297/R299 results; its then-pending review is not borrowed approval. The two named active-session rollouts supplied dated context, not execution authority or continuously current truth.

Canonical evidence sources are the relevant committed Borland mechanism/conditional-emission notes, original-identity/runtime-fingerprint notes, matching annex and their named original bytes/proof artifacts in `/home/lucas/work/johnny-castaway` and `/home/lucas/work/simtower`. The BCC/TASM/TLINK profile data must retain each selected fact's exact artifact/version and coordinate/consumer qualification. Current concurrent research is not imported automatically; verify a newly needed fact at its owner before use. The other workspaces, original inputs, labs and active sessions remain read-only.

Implementation may change this extension, the evidenced decompiler owner chain and directly affected tests/documentation, plus root-owned planning, task-log and changelog records. Operational build/import/MCP validation artifacts use fresh task-scoped directories under `/home/lucas/.cache/codex/`. Static analysis may import source-qualified local originals into fresh task-owned Ghidra projects; it may not execute those original games, compilers, assemblers or linkers. Do not package proprietary executables/libraries, old repositories, cache evidence, credentials or existing user analysis projects.

Only directly necessary Ghidra source/build followers of the confirmed decompiler change are admitted; unrelated original files remain untouched. No MCP implementation/configuration change, global installation, existing-project mutation, legacy-toolchain execution host change, external upload/push, old-repository deletion or unrelated cleanup is authorized. The existing source projects' standing RE continuation permissions do not attach those tasks here.

## Matching runtime and build proof

Use a task-private matching-source 12.3 DEV distribution to validate the changed native decompiler, Java extension and MCP together. The repository's native distribution/build machinery owns compilation and packaging; a private immutable-source export is appropriate because native Make/Gradle outputs are not all redirectable away from source directories. This is not an additional Git worktree, second maintained source owner or replacement of the user's installed 12.1.4 runtime. The historical runtime remains a comparison baseline, not a compatibility target inferred from its previous use.

Read-only readiness recon found GCC/make/Python and the prior Gradle executable, but no JDK25 in the checked system candidates and no repository dependency directory. Native decompiler regression compilation also needs BFD development files absent at the checked system paths. These are declared existing build requirements, not new product dependencies. Resolve the required development tools/dependencies in task-private locations before the first native execution; do not change system configuration or another session's resources. Native focused regression tests provide the early oracle; the matching full runtime provides the integrated Java/MCP proof. Do not substitute a 12.3 native binary into 12.1.4 and assume protocol compatibility.

Starting the corrected decompiler requires a process from the matching private runtime. Loading the extension requires that module at process startup. Retained 12.1.4 results are reused only for unchanged source facts, not as proof that the new runtime or changed C output passed.

## Primary-path acceptance

1. One integrated extension-plus-decompiler delivery covers every admitted capability group above, with explicit per-image/family coverage and a working matched build. Internal Worker batches are integrated into one delivered result; unfinished groups are not silently deferred as later product increments.

2. On qualified fresh tool-image imports, the profile's mapped regions, types, function boundaries/contracts, tables and references agree with the named original bytes and direct consumers. Dynamic-state and partial-layout limits remain visible rather than being converted into false global types or call targets.

3. On the demonstrated helper/caller and NE/pattern cases, native Program assertions and the relevant raw instruction/p-code or HighFunction observations establish the applied behavior. Revalidate the existing F_SCOPY path on the matching runtime and verify causally affected followers. Do not claim caller propagation or memory effects from a signature or synthetic expectation alone.

4. NB02 observations distinguish the demonstrated initial/footer records and position relations without claiming a symbol/type importer. Pattern annotations distinguish established mechanisms from compiler/version attribution.

5. Current native output for the real TLINK writer/F_SCOPY cases preserves the evidenced selector-dependent memory expressions, offsets and access widths, including the implicated dereference/array-member paths. The real-versus-synthetic stack-reference distinction is tested at the current owner. Directly affected nonsegmented C and inherited printer followers retain their established behavior. No claim of historical C, selector validity, alias/fault-sensitive equivalence or complete segmented-program reconstruction exceeds the observations.

6. The existing MCP can observe the integrated standard Program and corrected C results on the matching private validation instance. Neither a running normal user's process nor global configuration is silently changed.

7. The native package/build, focused current-owner validation, committed integrated candidate and current-user-selected completion Code Gate are complete. Documentation states actual coverage, the required matching runtime and remaining unproved semantics. Only the admitted extension/core follower frontier enters the change set; source repositories and unrelated `.refs/` state remain untouched.

## First verifiable slice and high-level work

The first directly verifiable slice is a focused native decompiler regression for the demonstrated loss: preserve a real selector/offset-dependent access as an address-valued expression with the correct typed read/write meaning, and establish the boundary with synthetic stack references. Use the existing native test owner and actual instruction/p-code foundation. Then reproduce the TLINK writer in the matching private runtime and apply an exact BCC4.5 backend-table/function-contract profile to establish the extension-to-Program path. This sizes execution; it does not reduce the final envelope or select a different architecture.

High-level work packages are matching build/toolchain preparation and segmented-expression correction; tool-image qualification/mapping and profile application; runtime-helper/flag/call analysis; NE relationship and NB02 structural analysis; and native/MCP integration, active documentation and delivery. The root's Microtask Program will set concrete Worker footprints and read dependencies after implementation is authorized. Parallelism requires disjoint effective writes and stable validation inputs.

Use native tools and focused owner/boundary checks. Do not add a maintained parser, inventory, verifier, manifest or transport to package proof when a bounded native command or native integration script directly decides the admitted property. Required evidence for exact input identity is byte equality between the named qualified input and the imported original bytes, not a generic hashing ceremony.

## Exclusions, lifecycle and next action

Explicitly excluded: a complete NB02 debug-symbol/type importer; Johnny-specific archive/resource loaders; generic historical compiler/version election; dynamic selector or overlay-runtime reconstruction; whole-tool/game semantics or complete original-binary reconstruction; broad upstream cleanup, an alternate printing language/server, or compatibility layers for unrequested runtime versions.

No material route decision is currently open. Core changes in the admitted decompiler chain are expressly authorized as a direction, not yet authorized to execute before the Plan checkpoint. An observed requirement to add another owner, general format/loading responsibility, external contract, Scope or risk returns to the current user. Do not silently omit an admitted image/family or substitute unsupported semantics when validation reveals such a boundary.

Plan Gate: local Senior Plan Auditor / Intent contract audit, Doctrine / Strategy reset, amendment transition not-applicable, returned `PROCEED` on `/root/legacy_integrated_plan_audit` for checkpoint `93168781a664c750a684f8c1e4047936f867790a`. All required bounded contract fields received complete coverage; no material findings or specialist consultation remained. The lead read the sole matching transition and placed this contract on hold in Strategy reset. No implementation has started.

Completion Code Gate: not yet selected for this new feature. Prior completed selections have expired.

Current blocker: later unambiguous current-user implementation authorization is pending after the completed Plan Gate. Next action: obtain that authorization, activate Implementation and dispatch the first bounded preparation/execution entries. Scope and the core-change decision are closed; do not ask the user to confirm those decisions again. There are no subordinate plan or microtask annexes. The [task log](../task-logs/2026-10-15-legacy-toolchains-integrated-expansion.md) records the planning outcome without owning Scope or lifecycle.
