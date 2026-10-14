# Place the validated extension inside the Ghidra fork

Status: complete
Task mode: Doctrine
Lifecycle phase: Closeout
Strategy epoch: 1
Plan kind: Targeted Adjustment Plan
Workspace: `/home/lucas/work/ghidra`

## Confirmed correction and authority

The requested result is to version the already validated legacy-toolchain extension inside the user's existing Ghidra fork, while keeping the extension isolated from Ghidra core. The earlier separate-repository placement was an implementation-placement error, not a requirement of independent extension architecture.

Current-user anchors, in this thread's source order:

- The user corrected the interpretation: `eu forkei, disse que não precisava modificar o código, não que não podia criar a extensão aqui`.

- The assistant then stated the exact delta: place the extension at `/home/lucas/work/ghidra/extensions/ghidra-legacy-toolchains/`, with no nested `.git`, preserve its validated code, add a local Gradle settings boundary, keep the old repository intact, and do not push automatically.

- The user answered `sim, confirmo`, explicitly confirming that complete delta and authorizing its Plan Gate through the result.

- After the Plan Gate returned PROCEED and the assistant asked to apply the transfer/build, the user answered `sim, por favor`, authorizing implementation of this reviewed correction.

- After candidate `8bf3c3642138d7eb8ece847c04a8ef171391f0cc` was committed and the assistant offered the three completion Code Gate options, the user answered `local`, selecting Senior Code Reviewer for this exact Gate.

The old first-increment task is complete. Its plan and validation are historical source/evidence, not a resumed execution authority. This plan owns the placement correction. The implementation authorization activated Implementation without changing the confirmed destination or preservation constraints. The later local review selection closed the remaining review-choice checkpoint.

## Before and required result

Before: the validated extension is committed only in `/home/lucas/work/ghidra-legacy-toolchains` at `70476eee3a31f966e28943db700333d23475d585`, with no remote. The current fork is `/home/lucas/work/ghidra`, branch `master`, origin `git@github.com:sangoi-exe/ghidra.git`, at `918acd744d17e3b95fbde44ec6ab3e59b6dbd45f`. Its tracked files are unchanged; untracked `.refs/` is pre-existing user state.

After: the extension's product/build sources and user guidance are tracked under `extensions/ghidra-legacy-toolchains/` in the fork. The directory has its own native Gradle settings boundary and retains project/module name `ghidra-legacy-toolchains`. No nested Git repository or source copy outside that owner becomes the active owner.

`Targeted Adjustment Plan` fits this finite placement/build-guidance correction. It adds no compiler functionality and does not refactor the analyzer or decompiler. Ghidra, MCP and game behavior remain unchanged.

## Scope and non-goals

- Transfer the existing tracked product/build files from the named extension commit, not `.git`, runtime aliases, build caches, originals or complete historical `.sangoi` records.

- Add the module-local settings file and update the product guidance for running the build from the module directory inside the fork. Record a bounded validation summary with an explicit locator for the first-increment evidence.

- Keep every pre-existing tracked Ghidra file and `.refs/` unchanged. Do not edit root `settings.gradle`, root `build.gradle`, Ghidra core, MCP or either game project.

- Preserve `/home/lucas/work/ghidra-legacy-toolchains` as a read-only historical source snapshot; do not delete it or maintain a second active implementation there. This task adds no runtime compatibility path for the old location.

- Root-owned task records belong under this fork's `.sangoi/`. Operational build/validation output belongs in a fresh task-scoped directory under `/home/lucas/.cache/codex/`.

- Create coherent commits on the current fork branch without staging unrelated paths. No remote push, history rewrite, global installation, existing-project mutation or original executable execution is authorized.

## Selected route and source evidence

The selected route is a standalone extension build nested at `extensions/ghidra-legacy-toolchains/`, but versioned by the enclosing fork. This is outside the directories enumerated by root `settings.gradle`. `gradle/support/settingsUtil.gradle` scans only `*/build.gradle` within each explicitly included directory. Recon established that the destination was absent and not ignored before the transfer.

Placing the standalone build directly under `Ghidra/Extensions/` would enter native root discovery and mix the already-selected installed-runtime extension build with Ghidra's source build. That is not the selected route. The module-local `settings.gradle` uses Gradle's native independent-build boundary; no custom loader, wrapper or include protocol is introduced. Preserve the existing project name so artifact/module identities do not drift.

The analyzer, prototype asset and focused native validation script remain the same semantic owners. The original source/runtime proof is retained under `/home/lucas/.cache/codex/ghidra-legacy-toolchains-20261014-RerJOP/`; the previous local Code Gate reviewed candidate `9adbacaba0a89a3c2e70470d0102204498c09f84` and returned PROCEED. That prior decision supports the unchanged behavior only; it does not approve the relocation or its new build boundary.

## Primary-path acceptance and first slice

1. Git in the fork tracks the extension at the confirmed path, with no nested `.git` and no changes to pre-existing tracked Ghidra files.

2. The relocated module's independent build works against the selected Ghidra 12.1.4/JDK 21 baseline and produces the same module/project identity. Root source-build discovery remains unchanged.

3. Analyzer, prototype and native test sources match the validated source bytes. Compare the newly built runtime payload with the previously executed module. Reuse native/MCP behavior evidence only when its relevant inputs/payload are unchanged; run a focused native check if the comparison exposes a relevant difference.

4. Active module build/use guidance names the new directory, and validation evidence has a truthful locator/summary. Do not imply the old repository remains an active build owner or that historical task records were copied into the module.

5. The fork change is committed, reviewed through the current-user-selected Code Gate, and handed off ready for the user's normal push. Old repository and original artifacts remain intact.

The smallest directly verifiable slice is the transfer plus independent module build. The decisive oracles are native Git source comparisons, native Gradle output and named runtime-payload equality, not a new maintained validator. This correction does not require another compiler investigation, whole Ghidra build or speculative test matrix.

## Implementation evidence

The bounded Worker transferred the nine named product/build paths from source commit `70476eee3a31f966e28943db700333d23475d585`, added the local settings boundary and validation summary, and updated product guidance. The module is inside the fork with no nested `.git`. The old source repository remains clean and unchanged. Fork commit `52599cf359566833d89fd833034733be00d8c35b` records the source/configuration/test slice; `8bf3c3642138d7eb8ece847c04a8ef171391f0cc` records current guidance and task records as a separate documentation checkpoint.

The relocated native build passed on Ghidra 12.1.4/JDK 21/Gradle 9.7.1 and reported only root project `ghidra-legacy-toolchains`. The lead independently verified the complete eleven-file frontier, the unchanged transferred source/assets, and all new JAR/source-archive entries against the previously executed module. Packaged current documentation matches the module. Pre-existing tracked Ghidra files are unchanged.

Detailed proof is summarized by [module validation](../../extensions/ghidra-legacy-toolchains/docs/validation.md); the [task log](../task-logs/2026-10-14-extension-in-fork.md) records attempts and delivery state. These are evidence followers, not additional Scope/lifecycle authorities. The relocation introduced no new native/MCP behavior claim or remote publication.

## Lifecycle and next action

Open material decisions: none. The completed task does not authorize changes to original Ghidra files, analyzer behavior, runtime ownership or external publication.

Plan Gate: local Senior Plan Auditor / Intent contract audit, Doctrine / Initial, amendment transition not-applicable, returned `PROCEED` on `/root/fork_extension_placement_plan` for checkpoint `1261a79f3358c329ab75d1cc6e047fc0d89e2bfc`. Required intent coverage is complete, with no material findings. The lead read the registered transition and placed this plan on hold in Initial before the later user implementation authorization.

Code Gate: the user's `local` selection authorized Senior Code Reviewer / Task change-set review, Doctrine / Implementation, for range `918acd744d17e3b95fbde44ec6ab3e59b6dbd45f..8bf3c3642138d7eb8ece847c04a8ef171391f0cc`. Task `/root/fork_extension_placement_review` returned `PROCEED`, with no findings or nits and complete semantic coverage of all three partitions and fourteen changed paths. The lead read the sole matching transition and entered Closeout. No remediation or review override was needed.

Current blocker: none. Closeout records only the produced review result and delivery state; it changes no reviewed module bytes. Existing semantic exclusions remain unverified, not new accepted functionality.

Next action: no task implementation remains. The fork commits are ready for the user's normal push. No automatic push, deletion of the historical source repository or instruction reload is part of this task.
