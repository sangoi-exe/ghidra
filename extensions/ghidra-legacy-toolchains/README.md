# Ghidra Legacy Toolchains

An independent Ghidra extension that turns qualified legacy-toolchain evidence into native analysis. The first increment recognizes the shared Borland `F_SCOPY` helper and models its implicit `CX` input, far-address argument storage, and far-return cleanup.

The extension is versioned in this Ghidra fork at `extensions/ghidra-legacy-toolchains/`. Its module-local `settings.gradle` retains a standalone installed-Ghidra build; it is not included in the fork's Ghidra source build and requires no nested Git repository.

Validated with Ghidra 12.1.4 and the existing Ghidra MCP 7.0.0 bridge. No Ghidra or MCP source patch is required. Far-address records are analysis representations, not recovered historical C types; emitted C is not a faithful representation of all segmented-memory operations.

- [Build and use](docs/usage.md)

- [Validation boundaries](docs/usage.md#semantic-limits)

- [Placement/build validation and prior behavior evidence](docs/validation.md)
