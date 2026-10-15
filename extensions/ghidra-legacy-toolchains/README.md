# Ghidra Legacy Toolchains

Native Ghidra analysis for qualified 16-bit Borland tool images and runtime correspondences. The extension applies exact-image profiles for BCC 2.0/3.1/4.5, TASM 3.1 and TLINK 4.01/5.1, plus supplied SCRANTIC and SimTower runtime profiles. Complete-body helper recognition, NE relocation provenance and NB02 structural observations complement those profiles.

The active source owner is `extensions/ghidra-legacy-toolchains/` in this fork. Its module-local `settings.gradle` retains a standalone installed-Ghidra extension build; it is not wired into the fork's root build. The integrated result also requires this fork's native decompiler changes and MZ loader correction, so build a matching Ghidra 12.3 DEV distribution with JDK 25 before packaging the extension against it.

Profiles qualify retained original `FileBytes`, not filenames or relocated-memory hashes. Analysis names, partial layouts, register tuples and far-address records are not recovered historical C declarations or proof of a program's producer. The fork's C view exposes typed selector/offset address expressions, not runtime selector resolution or host-compilable historical source. All eight profiles retain their established automatic-validation proof; those profile runs were not repeated for the latest SDK correction. The matching native decompiler now uses declared compiler stack-selector metadata for real call arguments, including the reproduced CALL_RETURN case without a same-address STORE. The sibling `extensions/ghidra-mcp/` 7.0.0 port again passes actual analysis and saves for three Programs plus C retrieval for five selected functions on that 12.3 SDK. MCP script execution and GUI installation/startup remain unverified. See the current [validation status](docs/validation.md).

- [Build and use](docs/usage.md)

- [Validation boundaries](docs/usage.md#semantic-limits)

- [Validation commands, evidence and remaining proof gaps](docs/validation.md)
