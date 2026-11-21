# Mint 0.6 Preview

Mint 0.6 Preview improves native decompilation, navigation and project recovery.

- **More x86-64 switches.** Mint recovers an additional ELF64 PIC jump-table pattern where the compiler uses a 32-bit index without a separate copy. It verifies the bounds check and the index used by the table before recovering cases.
- **Clearer decompilation results.** Android and headless output report whether a result is complete, partial, unsupported, limited by a resource budget or failed, with reasons when available. Unresolved jumps show where recovered control flow stops.
- **Pseudo-C to disassembly.** Tap a mapped statement to open its machine-code range in the listing. Back restores your scroll position in Pseudo-C.
- **Project recovery.** Save failures identify the failed step. Added checks for interrupted saves, insufficient storage, damaged analysis caches and restarting after Android terminates the process.
- **Analysis regressions.** Added a reproducible AArch64 and x86-64 ELF64 corpus with debug and stripped builds. Tests compare edited projects against fresh analysis after patches, prototype changes, undo, redo and reopening.
