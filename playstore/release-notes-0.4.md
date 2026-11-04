# Mint 0.4 Preview

Mint 0.4 Preview expands native binary analysis on Android and improves the workspace. It remains a preview: architecture, format, decompiler and debugger support are incomplete.

## Workspace

- Refreshed the interface with a mint-green Material theme and grouped workspace actions.
- Added built-in Ukrainian and English help with illustrative, highlighted examples.
- Added byte-order information to the memory-block report.

## Analysis

- Added big-endian AArch64 ELF64 and raw data support, including supported ABI and DWARF paths.
- Expanded selected ARM/Thumb VFP and NEON, RISC-V floating-point and atomic, AArch64 LSE and x86 LOCK semantics.
- Improved bounded memory dependencies, direct-call effect summaries, structure evidence, and incremental reanalysis for supported changes.
- Expanded supported DWARF, PDB/CodeView and Microsoft C++ RTTI metadata.

## Debugging and extensions

- Added process-qualified thread selection for negotiated all-stop RSP multiprocess targets, retaining legacy thread IDs.
- Expanded remote debugger module and register-description handling.
- Added a separate Android isolated-process mode for supported plugin commands. Trusted native plugins remain unrestricted.

## Automation

- Added a host batch runner with checkpoints, resume, retries, per-stream output limits and read-only analysis commands.
- Expanded supported version-tracking instruction correspondence and conservative annotation transfer.

See [the 0.4 status](update_0_4.md) and [README](README.md) for supported cases and remaining limitations. The batch runner is a host tool; it is not an Android workspace screen.
