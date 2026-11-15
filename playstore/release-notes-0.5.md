# Mint 0.5 Preview

Mint 0.5 Preview improves interprocedural analysis and recovery of optimized native control flow on Android.

## Recursive memory analysis

- Added bounded memory-effect summaries for supported recursive groups of verified local direct calls.
- Summaries are published only after the whole supported group converges. Unknown effects, possible aliasing and exhausted budgets retain conservative barriers.

## AArch64 pointer and layout evidence

- Added bounded propagation of pointer-argument and field-layout evidence through verified local AArch64/AAPCS64 direct calls.
- Accounts for constant pointer offsets and conflicting layouts while preserving the priority of user and debug declarations.
- Inferred layouts can appear as evidence comments; named field expressions still require supported authoritative declarations. Type evidence does not imply no-alias or read-only behavior.

## x86-64 switches and tail calls

- Added early recovery of guarded ELF64/x86-64 PIC switch tables with signed 32-bit relative entries, exposing previously missed case blocks during discovery.
- Preserves case-to-target mappings, including several cases sharing one target.
- Supports verified direct tail-call exits to known function entries while keeping handlers as separate functions.
- Emits `return handler(...)` when compatible authoritative scalar SysV64 declarations and actual argument bindings are proven. Other verified transfers remain explicit low-level terminal operations.

## Reliability and validation

- Added semantic regression coverage for recursion, aliasing, conflicting type evidence, switches, tail-call argument bindings and resource limits.
- Added lifecycle comparisons for patches, prototype changes, undo/redo and project reopening against fresh analysis.
- Added optimized Clang switch fixtures with sibling-call optimization enabled and compilation/execution checks for supported generated C.
- Documented the production roadmap and acceptance gates for a future working 1.0.

## Preview scope

These are bounded extensions, not complete ISA, ABI, heap or C++ recovery. Tail-call memory summaries remain conservative barriers; indirect tail calls, stack/FP/aggregate/variadic tail-call arguments and arbitrary switch idioms remain outside the new support.

The APK supports Android 8.0+ on ARM64 and x86-64 devices. See the repository README for the full support matrix and limitations.
