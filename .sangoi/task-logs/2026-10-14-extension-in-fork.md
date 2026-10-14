# Extension placement correction

Date: 2026-10-14, America/Sao_Paulo. Lifecycle: Closeout. Status: complete.

## Authority and correction

The [canonical placement contract](../planning/2026-10-14-extension-in-fork.md) owns the confirmed destination and current-user anchors. The user corrected the separate-repository interpretation, confirmed `extensions/ghidra-legacy-toolchains/`, and authorized the transfer/build with `sim, por favor` after the local Plan Gate returned PROCEED.

The extension is now owned by this Ghidra fork. The historical standalone repository at commit `70476eee3a31f966e28943db700333d23475d585` remains intact and unchanged. No nested Git repository, compatibility path, new compiler behavior, or modification of the original Ghidra build was introduced.

## Implementation and validation

Worker `/root/fork_extension_placement_impl` exported nine product/build files from the immutable source commit, added native module-local settings and a bounded validation summary, and updated the in-fork build guidance. The seven non-documentary transferred files remain byte-identical to the source, including analyzer, XML and native assertion script.

Native Gradle 9.7.1 with Ghidra 12.1.4/JDK 21 evaluated the nested module's settings/build files, reported root project `ghidra-legacy-toolchains` without subprojects, and built the extension successfully. Build output, caches, preferences and temporary state belong only to `/home/lucas/.cache/codex/ghidra-fork-extension-placement-20261014-Gp2ovM/worker/`. The root independently checked the exact eleven-file module frontier, enclosing Git ownership, source equality, nine-file package inventory, runtime/archive-entry equality, current packaged documents and source-repository preservation.

The compiled JAR, source archive and runtime assets match the previously executed module. Prior native/MCP behavior evidence is reused only for that unchanged payload; no fresh native/MCP execution or whole Ghidra build was claimed. [Module validation](../../extensions/ghidra-legacy-toolchains/docs/validation.md) owns the concise proof and historical evidence locator.

Two initial ad hoc evidence checks misclassified their own shell process and normal Git no-index difference status. The checks were corrected without product changes. A local documentation-format correction inserted blank lines between evidence-list items and refreshed the ZIP; only that packaged document changed. The final native build/comparison statuses are zero. No task-owned build/runtime process remains running.

## Delivery boundary

Fork commit `52599cf359566833d89fd833034733be00d8c35b` records the source/configuration/test slice on `master`; candidate `8bf3c3642138d7eb8ece847c04a8ef171391f0cc` adds current guidance and task records as a separate documentation checkpoint. Pre-existing Ghidra tracked files and untracked `.refs/` remain outside the change set. Source/build settings of the parent repository are unchanged. No source repository was deleted, no Git history was rewritten, and no push was performed.

## Local Code Gate and Closeout

The user answered `local` after the assistant offered the three Code Gate choices for this committed fork candidate. Senior Code Reviewer `/root/fork_extension_placement_review` reviewed range `918acd744d17e3b95fbde44ec6ab3e59b6dbd45f..8bf3c3642138d7eb8ece847c04a8ef171391f0cc` and returned `PROCEED`, with no findings or nits. All fourteen candidate paths and all three required partitions received complete semantic coverage. No required surface was unreviewed or evidence-blocked. The reviewer independently inspected retained build/native/MCP evidence and source/archive equality without running a new build or product runtime.

The root read the registered `PROCEED` transition and entered Closeout. This follow-up is `bookkeeping memorialization`: the plan, task log and changelog record the produced result; no reviewed module byte or runtime claim changed. No corrective Worker batch, new Gate or material decision was required. Final delivery inspection retains only pre-existing untracked `.refs/` outside the committed task. The fork is ready for the user's own push.

Existing exclusions remain explicit: no new native/MCP execution for relocation, no GUI/Real Mode/general corpus validation, and no proof of segment-faithful C. Loading the Java extension requires a new Ghidra process with the module present at startup; no existing installation or process was changed by this task.
