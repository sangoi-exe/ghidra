# Local RE commit frontiers and reusable findings

This report records the previous Johnny Castaway and SimTower commit screenings, the useful evidence recovered from those screenings, and a finite follow-up of local commits. The user requested this record on 2026-10-15 while Ghidra's compiler-stack selector correction continued. This is an evidence report, not another implementation plan or authority to add features. The [preceding Intent Contract](../planning/2026-10-15-legacy-toolchains-integrated-expansion.md) is complete. The user subsequently selected four candidate groups plus five reproduced corrections under the [current Intent Contract](../planning/2026-10-15-safe-legacy-profile-candidates.md); that plan owns product Scope and status. The implementation disposition below does not move the fixed screening frontiers.

The commit sweep uses fixed local Git objects, with bounded historical rollout and retained-proof evidence where stated. This sweep did not fetch, use GitHub, execute original programs or modify either RE repository. Human-facing times below use `America/Sao_Paulo` with offset `-03:00`.

## Exact frontiers

| Repository | Branch | Previous inclusive subject-screening cutoff | Reachable subjects at that cutoff | New fixed review tip | New subjects | Tip observation |
| --- | --- | --- | ---: | --- | ---: | --- |
| `/home/lucas/work/johnny-castaway` | `main` | `5e6c9dbe88e0f5cd9d48e9056415069b912450a0` | 1,136 | `7841f14702410ea427d373fcc4908efa3e29d225` | 19 | `2026-10-15T19:05:00-03:00` |
| `/home/lucas/work/simtower` | `main` | `e90bb42a20d333a6fa8b3c35f2ca330a213589c5` | 310 | `c7daad1f9df2ecde55021612fabe4a0c9bf261e5` | 22 | `2026-10-15T19:05:20-03:00` |

Both old cutoffs exist and are ancestors of their fixed review tips. Native Git checks reproduced the old reachable counts and the new range counts. All 41 new subjects were screened. Only selected promising diffs and their evidence received substantive review; neither the old nor new subject screening is a complete semantic audit of every commit.

The fixed tips are the continuation points for a later sweep. The agents rechecked HEAD after their bounded reviews and found the same tips. This report does not cover subsequent commits or uncommitted work. Johnny's initially clean checkout acquired six modified documentary paths during inspection; SimTower already had uncommitted work, including an untracked BCC4.5 cleanup note. Those bytes were excluded. Committed-note readings used the fixed Git objects, not changing working files.

### Post-cutoff evidence already considered

Johnny commit `5c3a67c6d2e0b422ed115be7653c5b9ec7b842c8` falls after the old subject-screen cutoff, but the Ghidra session had already inspected its R297/R299 results. It belongs to the new 19-commit range for accounting, but it is not wholly new knowledge. Historical inspection is established; a direct commit-to-shipped-code dependency is not. This exception does not move the previous whole-list screening cutoff.

## Historical recovery evidence

Source session: `01a13bb1-5597-7090-a92b-8426359342a8`. Exact rollout: `/home/lucas/.codex/sessions/2026/10/14/rollout-2026-10-14T15-33-59-01a13bb1-5597-7090-a92b-8426359342a8.jsonl`.

| Source line | Evidence |
| --- | --- |
| 1600 | Historical CommandExecution at `2026-10-15T09:34:14.970-03:00`: both source branches were `main`, with the exact cutoff HEADs and counts above. Ghidra was `master` at `357c77c44762013e4fbbf8c71f477709c086d99a`. |
| 1636, 1649 | Independent SimTower compiler and format Recon reports account for all 310 subjects, followed by selected owner/diff review. |
| 1665 | Johnny linkage Recon accounts for 1,136 subjects and 126 linkage-keyword matches; selected matches received semantic inspection. |
| 1702 | Johnny compiler Recon accounts for 1,136 subjects, with 170 predicate matches and 966 nonmatches; selected mechanisms and originals were checked. |
| 1719, 1753, 1778 | Bounded follow-ups add NB02/header/output and exact-tool profile evidence without establishing a later whole-list cutoff. |
| 1799 | Root CommandExecution at `2026-10-15T09:49:19.022-03:00` reads the exact committed `5c3a67c6…` task log, including R297/R299. This supersedes the earlier session report that those results were still unpublished. |

The root recovered the request for this report at source line6012, turn `01a14191-9edd-7aa0-a71d-9332470b6fcb`, `2026-10-15T18:59:32.980-03:00`. Three read-only lanes supplied the bounded evidence: `/root/legacy_commit_frontier_recon`, `/root/johnny_new_commits_recon` and `/root/simtower_new_commits_recon`. Their conclusions were reconciled with native Git commit identities and range counts.

## Useful historical commits

The following is a recovered useful-evidence ledger, not an exhaustive attribution of every extension line to a source commit. `Documented implemented` means the corresponding capability is described in Ghidra checkpoint `65353a0d9347fc4f6f25cebdd282551d7ab3c965`, principally `extensions/ghidra-legacy-toolchains/docs/usage.md` and `docs/validation.md`. It does not claim that this report independently revalidated that implementation. `Supporting` and `considered` must not be read as shipped behavior.

### Johnny Castaway

| Commit | Useful evidence | Disposition and limit |
| --- | --- | --- |
| `dd067fa8e9c63c463234ae02626a78aa0d543eb8` | Complete 33-byte F_PCMP vendor correspondence and finite-word/flag contract. | Documented implemented: qualified recognition and ZF/AX/DX/BX/CX analysis result; not an AX Boolean or raw-pair equality. |
| `732ff299ba6ed7de77db96caa84ccb21d2b06f90` | Original pair-comparison helper mechanics before vendor correspondence. | Foundational evidence for the same F_PCMP family. |
| `57bc10ca87d901f03133b9138b8a2363b9c2ea9e` | Complete 69-byte setmem/memset family; wrapper returns current post-call SI before restoring it. | Documented implemented as separate 40/29-byte helpers with WORD storage/results and qualified frames, not unrestricted modern memset. |
| `bcba9441b70017e61bf1797bef54ec114b633305` | Word-pair shifts: near adapters, far cores, DX:AX/CL, BX scratch and bounded count effects. | Documented implemented as three nonoverlapping far cores plus near labels; mathematical qualification is CL0..31. |
| `599ba65f036f8d63cedb524a914fb3c8d8914dc2` | Bound supplier chain with complete 43-byte LSEEK correspondence. | Documented qualified correspondence, not interrupt/transitive-effect proof. |
| `e13f91e5fd3c4b2dad4842c110059d94f3a0fdc0` | Genuine FHEAP geometry and compiler-register interface calibration. | Supporting SCRANTIC heap/runtime profile evidence; not historical ABI attribution. |
| `002e72349de1dfb4bb49dae941796c4407cce513` | Selected bound getter/supplier correspondence. | Supporting heap/runtime evidence; interior matches do not establish allocator equivalence. |
| `cfbba8f8058c4454ea2a89514ee3e7d517b3e63b` | TLINK changes FAR16 calls to `90 0E E8` while retaining the far-return stack relationship. | Useful structural foundation. Native PUSH CS/CALL/RETF semantics already existed; this ledger does not establish a separate general provenance classifier. |
| `d27c9dee71bcad6c00e6a1a6ba1ab361be39a46e` | Qualified BCC backend/state, TASM four-byte shortening and TLINK five-byte rewriting/writer mechanisms. | Documented exact-image profile evidence; not generic compiler identification on unknown game code. |
| `95c12db1d505437a11d89be3215592a2b534d548` | NE defined-entry/export distinctions, ordinal relocation resolution and resource bounds. | Foundation/negative corpus for qualified provenance, not replacement of Ghidra's loader. |
| `8951c1d3f50bf73bb3de5b9a0906b420c5e096b6` | R181/R187 complete NB02 initial-record and terminal-footer distinctions. | Documented bounded structural observations; full debug symbol/type import remains excluded. |
| `499a756e7bb1c3b088f39d8b978824f6855a3b2b` | R192 separates object offsets and post-emission call padding. | Supporting NB02/control qualification, not a complete debug grammar. |
| `134d1d0b8e87d2b447d9f2850ff994bf273f3d29` | TASM `/o` preserves 180 CODE bytes and changes the qualified `__AHSHIFT` fixup kind; all 18 object fields agree. | Considered toolchain control evidence; closes an object-production distinction only. |
| `5c3a67c6d2e0b422ed115be7653c5b9ec7b842c8` | R297 three-byte complete-file delta and R299 original-gap recomposition. | Already considered after cutoff. No direct shipped-runtime use established. R299's 21,952-byte equality is with R38-L2, not the supplied 295,952-byte original. |

Historical source owners include `.sangoi/research/compiler-assisted-function-reconstruction.md` (F_PCMP, bound suppliers and matching qualifications), `.sangoi/task-logs/2026-10-12-vendor-fill-member-correspondence.md`, the BCC/TASM/TLINK mechanism notes, and the original-byte `runtime_program_semantics.py` records named by the Recon messages. Resolve these paths in the relevant source commit, not by assuming current line numbers remain stable.

### SimTower

| Commit | Useful evidence | Disposition and limit |
| --- | --- | --- |
| `fb722be6e8905225d0109e97ef488bc240211367` | Original NE1 `[1222,1248)` matches the 38-byte Borland copier. | Documented implemented: caller-owned ten-byte arguments and DX:AX offset/selector result, distinct from F_SCOPY. |
| `c95655cf8bdd4e6208dc8a566ced83e8b4d65528` | Genuine vendor/source anchors, copier aliases and CRT/startup foundations. | Supports far-copy/runtime profiles; shared bytes do not identify an exclusive release or name. |
| `4031c83697a317d17d884754954d347c55408010` | Connected copier/startup/EXIT/XXV/formatting comparisons. | Documented qualified correspondences, not complete runtime models. |
| `332961788c52e5bc106961268125838e284ba9ba` | 378-byte C0WL4.5 startup topology and qualified differences. | Supports startup/profile evidence, not whole-application memory-model attribution. |
| `2311b6e5b2d724426e9abb67c303ba03d87c0cae` | Startup configuration controls and provider comparisons. | Supporting runtime-profile evidence. |
| `9e9a521b594e0fb32d137c48b8ac24cecff42f06` | WAVMIX selector-only relocation preserves a literal CALL offset; an immediate-WORD fixup is not itself a call. | Documented qualified NE provenance; no invented loaded value or replacement parser. |
| `00fbe6f8fb07f53a96d27ba9e3ee8c461e4dc197` | Mixed-width DWORD return boundaries and native request suppliers. | Useful constraint/candidate; no generic idiom analyzer established by this record. |
| `8c84acc0e3ac55c53f4f78b69df7e42bdbeafd9d` | Qualified BCC SHLD requests and return-view confirmation. | Exact-tool annotation evidence, not a universal DX:AX ABI. |
| `3d5297c771765dd2c164005a7d10c3117f05dadd` | A complete 39-byte body reproduced with `_EAX`; upper halves/CF differ from split-WORD reads. | Demonstrated capability and negative control, not recovered historical source/type. |
| `fac5626f82ef16fc9cd556688aed44efd4e6197b` | Conditional BCC/TASM callback, backend, width and control mechanisms. | Documented exact-image profile category, not unknown-game producer inference. |
| `f95d48c27ebb70ef46662b37256a2a8e58828046` | Qualified scalar-zero and OR-self mechanisms with category/lifetime limits. | Useful profile/constraint evidence, not generic source-expression recovery. |

Historical source owners include `.sangoi/research/windows-toolchain-fingerprints.md`, `windows-original-identification.md`, `windows-table-transfers.md`, `windows-row-associations.md`, `windows-publication-request-chain.md`, and the qualified BCC/TASM mechanism notes. Their original-byte and platform-authority qualifications remain applicable.

## New local findings: Johnny Castaway

All claims in this section are bounded to the fixed Johnny tip above. The Recon classified ten substantive commits and nine review/qualification closeouts through their changed-path frontier and selected committed evidence. Private proof files were not exhaustively rechecked.

### Exact-image BCC profile candidates

| Commit | New knowledge | Potential existing owner and qualification |
| --- | --- | --- |
| `7281647214e0155f8a7a3dcb2bfa9e5eb0d9070e` | BCC3.1 R320: complete NE58 `[15FC,1999)` lowering body, 925 bytes/350 instructions; a qualified zero-pair arm bypasses immediate `pcmp@` name construction. R329/R333: complete NE52 `[1026,12F2)` record-preparation body, 716 bytes/261 instructions, high-before-low child results and fresh DX:AX on all eight exits. BCC2.0 R335: individual register/immediate-zero requests can select self-XOR under the established chronological conditions. | Extend existing `Bcc31Profile`/`Bcc20Profile` boundaries, annotations, references or partial layouts. These later complete mechanisms were not represented in the bounded stable-profile comparison. They do not prove actual R310/R306 traversal, unconditional pointer identity, a source type, or the producer of two wide-argument requests. |
| `cd1cdda0b2b50342260643ab320098f91e919e27` | BCC2.0 R357/R363: complete overlay0508 selector helper `[0847,08A8)` and operand constructor `[08A8,09CF)`, together 392 bytes/133 instructions. Conditional selector writes, ordered contributions and recursion; neither initializes a whole destination. | Additional functions/record annotations in the existing exact FBOV analysis block. No new loader is implied. Numeric selectors/tags are not yet proved register names, source addition or a final address form. Preserve AL/AH and fresh second-child/alias-sensitive ordering. |

Canonical committed evidence: `.sangoi/research/borland-toolchain-mechanisms-bcc.md` (R320/R335), `borland-bcc31-record-preparation.md` and `borland-bcc2-address-operands.md`. The Recon directly inspected selected R335/R357 proof records; remaining opaque callees, state lifetimes, recursion termination, unreviewed builder arms and physical serialization stay open.

### Regression corpus and overlap

| Commit(s) | Useful result | Classification |
| --- | --- | --- |
| `fd9dbcad5522fd4208446e90e4be487c710eb3e8`; supporting `538e4e0a3c8c4893e6fcf4032ad9fb5d7e3031be` | R319: complete original NE7 `[1112,124A)` helper, 312 bytes/161 instructions, seven far returns and actual bindings. Earlier contrasts distinguish increment shapes and BCC3.1 `-Z` reload suppression. | Candidate decompiler examples for current-return stores, fresh DS/frame reads, signed loops and FAR returns. No Ghidra defect demonstrated. R310's source comment predicts normalized comparison, but actual output is raw MOV/OR/JE with no F_PCMP fields; source spelling is not a semantic oracle. |
| `4eb7baf78e434dce55bd1dfe98a97d1a25a49cb7` | Corrects private-input timestamp qualification. | Retain the correction; no new code-generation causality established. |
| `ad11ce2e83769c925ee38eea13131d5b5652c31c` | R346 folds four address expressions into operands; R348 isolates a signed-subtraction contrast. | Useful address-domain/finite-arithmetic/FLAGS examples. Equal final modular addresses do not prove valid intermediate pointer arithmetic; removed ADDs change BX/FLAGS. No observed Ghidra failure. |
| `428ebb886cb14d385eb7fc4c4da0403a4d06adf4` | Four connected provider helpers totaling 269 bound C bytes; later R355 strengthens genuine-input ownership. | Primarily reconstruction/regression corpus, not a missing generic feature. |
| `7de71eaefd99f68da3d962eeab0ef03c458f1793`; `7841f14702410ea427d373fcc4908efa3e29d225` | R378: eight bodies, 1,303 bytes/606 instructions. R393–R396: ten bodies, 1,686 bytes/767 instructions, including the earlier 1,303 bytes once. Later evidence includes applicable Borland3.1 Win16 header/import-library foundations. | Copy-direction, current SI/DI, consumed-return, ordered-store and imported-call examples. SDK identities are qualified platform foundations, not automatic numeric-owner renames. The latest 39,872-byte fixture is not the complete 295,952-byte original and still contained copied context and outstanding review. |
| `5c3a67c6d2e0b422ed115be7653c5b9ec7b842c8` | R297/R299 fixup/layout results. | Already considered after the old cutoff; implementation use not established. |
| `c878dc02b2cdb3f9277cae70fbb7123ba8bcdcdd` | R301 closes the old H04 188-byte import-overlay mismatch with unchanged-body `/o` assembly/link. | Reinforces existing relocation/provenance knowledge; not a universal `/o` recipe or a new relocation feature. |

Emitted equality is not proof of defined C, loaded ABI, transitive effects or historical source. The connected reconstruction notes and matching annex remain the source owners; this report does not replace their artifact/control qualifications.

## New local findings: SimTower

All claims in this section are bounded to the fixed SimTower tip above. All 22 subjects and changed-path sets were screened; semantic reading focused on runtime fingerprints, allocation/serialization mechanisms and directly related body/relocation evidence.

### Distinct runtime-helper candidate

`090bd2e26518942062388c8182b3a56e40e03ae8` — **Reconstruct signed-length copy and text-extent wrappers**.

The committed `windows-toolchain-fingerprints.md` section “Whole genuine move provider and actual far-entry binding — RF27/RF28” qualifies a complete genuine 298-byte object with a 128-byte CODE contribution: an 89-byte `__fmovmem` core at0000 and a 39-byte `__fmemmove` wrapper at0059. The contribution reportedly matches original NE1 `[10E8,1168)`. The core chooses copy direction using selector/offset relationships and leaves CLD; the wrapper forwards five WORDs, PUSH-CS/near-calls the core, cleans ten bytes and freshly returns destination DX:AX. Original NE67 selects NE1:1141, the wrapper, not the core; actual linked-public evidence corroborates that binding.

This is a distinct candidate for the existing qualified-helper extension. Ghidra's 38-byte `BorlandFarCopyAnalyzer` explicitly models a different forward-only copier, not memmove. The new result does not invalidate that helper. A later implementation must independently qualify the complete bytes, both entries, direction/flags/register effects and actual caller relationships. Caller-specific signed-BYTE count extension and source-offset wrap without selector carry must not become universal helper guarantees. Valid selectors, capacities, historical producer identity and native equivalence remain unproved.

The vendor archive reader rejected an A3 comment; actual TLIB extraction omitted that comment. This observation does not authorize arbitrary record filtering or establish complete archive-parser support.

### Existing behavior reinforced and compiler-profile knowledge

| Commit(s) | New knowledge | Disposition and limits |
| --- | --- | --- |
| `c9ac9f526823512a8e26476045db3231d4bb6e9b`; `c2bbbdd5035b6b2625d22af8beb7cebbf27e6364` | Genuine CWL31 `H_LRSH`: three-byte near adapter plus 29-byte far core, complete 32-byte contribution matching NE1 `[31D0,31F0)`. Actual compiled/linked signed shift selects the far public at offset3/NE1:31D3. Count4 uses DX:AX/CL, BX scratch; CL exits12 and final OR flags describe the low WORD only. | Existing `BorlandWordPairShiftAnalyzer` already represents the arithmetic-right pattern, adapter/core split and bounded count effects. New value is genuine-member/public provenance and actual binding, not another mathematical shift feature. Shared bytes do not discriminate historical releases. |
| `454a05ea4ad3a1aa5479f6be7c49f2f8a1148d05` | RF26 separates BCC4.5 IMUL003E result selection from source/immediate materialization. Conditional pending entries may request register transport and update cached selection. | Exact-image profile/annotation candidate. `_BX` assignment does not prove IMUL ran in BX; tag2/4 annotation is not direct003E allocation. Actual RF24 node/index/mask/history remains unjoined. |
| `f2d9eeb0bbf699cf8cc2fc4c11821cf7eb5fb4d4` | RF30: the selected0039 ASM formatter writes literal `ax,ax,`; NE49:109E is a cache/flag query returning AL or FF with AH uncleared, not a scaled-address builder. | Preserve the correction at any future annotation owner. ASM text alone does not identify003E or three allocated operands. No matching incorrect assumption was found in the bounded Ghidra comparison. |
| `c7daad1f9df2ecde55021612fabe4a0c9bf261e5` | RF31: a qualified frontend path constructs003E directly; formatter consumes current A659 fields after prior helper effects. | Not proof of0039→003E rewriting or stable pre-callback state. Actual RF24 traversal, allocation lifetime and source equivalence remain unresolved. |
| `c7cedb3801f1e334c105c117deb05badcf8f30ac` | RF25 corrects an earlier instruction count: six wrapped byte-continuation rows were not instructions;155 actual instructions, not161 displayed rows. FatalAppExit wrapper still has its ordinary restore/RETF suffix if the opaque import returns. | Retain accounting and return-path qualifications. Neither an import name nor platform intent proves unconditional noreturn. |

Canonical committed owners are `.sangoi/research/windows-toolchain-fingerprints.md`, `windows-ne67-prefix-layout.md` and `borland-bcc45-register-allocation.md` (RF26/RF30/RF31), with direct conditional-emission corrections. The remaining review/ledger, palette/font/graphics and regional-matching commits mainly advance SimTower reconstruction rather than establish reusable extension features.

## Subsequent implementation disposition (2026-10-16)

Ghidra product checkpoint `218a8564f617185cb9e0820d74b8fff7b361f32d` implements the four selected groups: the complete move family, BCC2.0 selector/operand and conditional XOR facts, BCC3.1 preparation/lowering facts, and BCC4.5 pending-selector/cache/literal/IR facts. The existing profile and helper owners remain canonical; original-byte, native-binding, partial-semantics and historical-attribution limits above still apply. The move family remains distinct from the earlier forward-only copier.

The [execution record](../task-logs/2026-10-15-safe-legacy-profile-candidates.md) links source readiness, correction attempts and cumulative proof. All eight native original-profile validators and the helper suite pass. Actual MCP consumption covers 21 selected new function records, seven C views and two descriptive record types. The exact Code Gate is still unselected and no reviewed-completion claim is made here. Later RE commits, source hypotheses, RF41 and the nonselected regression corpus were not silently absorbed.

## Recommendations at the screening checkpoint

1. Finish the already-selected compiler-stack correction and its validation. None of the new commits changes that admitted route or supplies permission to fold in unrelated features.
2. For a later capability decision, the strongest distinct helper candidate is the whole overlap-aware move provider. The strongest existing-profile additions are Johnny's complete BCC3.1 lowering/record-preparation and BCC2.0 selector/operand mechanisms. Compare these bounded owners with their actual retained bytes before implementation.
3. Treat SimTower's BCC4.5 allocation/formatter findings as qualified exact-tool annotations and constraints, not a source-recovery recipe. Preserve the corrected cache-query interpretation and literal formatter behavior.
4. Use the connected C matching work as a regression corpus only when a requested property or observed Ghidra failure identifies a relevant test. Regional equality alone is not a reason to add a large permanent test matrix.
5. Retain already-implemented overlap as stronger provenance, not duplicate analyzers: arithmetic shifts, F_SCOPY, the forward-only copier, and NE import-overlay observations have existing owners.

These were recommendations for later user selection. No new helper, profile function, source hypothesis, platform-name import or test suite was admitted or implemented by this sweep. Subsequent selection and execution belong to the current Intent Contract linked above; the recommendations in this section remain a historical account of the screening result.

## Coverage and continuation limits

The historical ledger is the bounded set recoverable from prior Recon messages, selected committed owners and the documented Ghidra capability baseline. It is not exhaustive commit-to-code attribution. The new sweep inspected all subjects in the two exact ranges and selected semantic evidence; it did not re-run compiler experiments, re-analyze original binaries, authenticate all SDK inputs, inspect every private proof artifact, validate game behavior or audit the entire Ghidra extension.

Some early discovery displays were truncated. Decisive historical messages, identifiers/counts and candidate passages were subsequently read in bounded selections. No completeness claim relies on a truncated display. Root independently checked every commit identifier listed above and both range counts with native Git; this is identity/accounting proof, not independent semantic reproduction.

For a later sweep, capture a new fixed local tip and compare it with the corresponding new review tip in the first table. Keep committed evidence and uncommitted work separate. A changed/retracted original-byte claim, public offset, relocation binding or instruction ordering can falsify a candidate; report that change rather than silently carrying forward the old interpretation. Keep the existing exact-tool qualifications and source repositories' original-only evidence rules.
