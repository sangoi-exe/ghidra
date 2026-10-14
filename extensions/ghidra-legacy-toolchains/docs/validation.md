# Placement and validation evidence

Date: 2026-10-14, America/Sao_Paulo.

## New placement/build proof

The active source owner is `extensions/ghidra-legacy-toolchains/` inside the Ghidra fork at `/home/lucas/work/ghidra`. The nine original product/build files were exported from Git commit `70476eee3a31f966e28943db700333d23475d585` in `/home/lucas/work/ghidra-legacy-toolchains`; that repository is preserved as read-only historical evidence, not a second active build owner. Only product guidance changed, with module-local `settings.gradle` and this summary added. The analyzer, XML prototype, and native assertion script remain byte-identical to that commit.

Native Gradle evaluated this module's settings/build files and reported one root project, `ghidra-legacy-toolchains`, with no subprojects. `buildExtension` passed against the installed Ghidra 12.1.4 PUBLIC and JDK 21.0.12.1+1 using Gradle 9.7.1. It did not build the fork's Ghidra sources or change parent build settings. Git ownership resolves to the enclosing fork; no nested `.git` or pre-existing tracked Ghidra changes are part of the transfer.

The task-private output owner is `/home/lucas/.cache/codex/ghidra-fork-extension-placement-20261014-Gp2ovM/worker/`. Build output, Gradle user/project caches, home/configuration, preferences, and temporary files were directed there. Evidence locators relative to that directory:

- `logs/transfer.log`: exact Git-object source and transferred paths.

- `logs/build-first.log`, `logs/build-first.status`: initial independent build and native project/settings identity.

- `logs/build.log`, `logs/build.status`: final documented package build, exit 0 with `BUILD SUCCESSFUL`.

- `logs/comparison.log`, `logs/comparison.status`: immutable source equality, executed runtime-payload equality, and final package inventory/document equality.

- `logs/ownership.log`, `logs/ownership.status`: enclosing Git owner, no nested repository/generated module files, unchanged pre-existing tracked Ghidra files, and preserved source repository.

The deliverable is `build/dist/ghidra_12.1.4_PUBLIC_20261014_ghidra-legacy-toolchains.zip` under that output owner. Its file inventory is `Module.manifest`, `extension.properties`, `data/borland-f-scopy.xml`, `ghidra_scripts/ValidateFScopy.java`, the compiled JAR and source ZIP under `lib/`, `README.md`, `docs/usage.md`, and this summary. Settings/build scripts, Git metadata, historical task records, originals, and operational caches are not packaged. Whole ZIP metadata equality is not claimed.

## Reused prior behavior proof

Every JAR entry name/content, every source ZIP entry, and the manifest, resolved extension properties, XML, and validation script match `/home/lucas/.cache/codex/ghidra-legacy-toolchains-20261014-RerJOP/m1/installed/ghidra-legacy-toolchains/`. This unchanged runtime payload supports reuse of the prior native/MCP execution evidence; no new native analysis or MCP process was run for the placement correction.

The full historical report is `/home/lucas/work/ghidra-legacy-toolchains/.sangoi/reports/2026-10-14-first-increment-validation.md`, retained in source commit `70476eee3a31f966e28943db700333d23475d585`. Its evidence owner is `/home/lucas/.cache/codex/ghidra-legacy-toolchains-20261014-RerJOP/`: `m1/logs/native-4.log` and `m1/validation-4/` record the fresh SimTower NE assertions; `i/results/` records actual stdio MCP analysis, script execution, function/type queries, save, and re-read. Those runs established CX and two four-byte offset/selector arguments, native void return, purge 8/stackshift 4/extrapop 12, and actual caller byte counts 16/8/8.

## Boundaries

Segment-faithful C remains unproved: the tested C view omits selector-dependent memory expressions. The prior TLINK writer probe is historical capability evidence, not an installed feature. No GUI installation, Real Mode execution, arbitrary binary corpus, whole-game recovery, original game/compiler/linker execution, new Ghidra/MCP integration, Code Gate approval of this relocation, or remote publication is claimed. See [semantic limits](usage.md#semantic-limits) and the historical report for the retained exclusions.
