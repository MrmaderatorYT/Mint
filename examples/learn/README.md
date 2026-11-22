# Mint Learn binaries

These offline lessons use small AArch64 ELF binaries with a named entry function and no external dependencies. The assembly sources keep the instructions students see stable across rebuilds.

| Bundled file | Entry function | Practice patch |
| --- | --- | --- |
| `arithmetic.elf` | `scale_score` doubles a score and adds 3. | Change `add w0, w0, #3` to `add w0, w0, #5`. |
| `branch.elf` | `choose_level` returns level 1 below a score of 8, and level 2 otherwise. | Change `cmp w0, #8` to `cmp w0, #10`. |
| `memory.elf` | `update_pair` adds the first two unsigned words in an array, stores the result in the first word, and returns it. | Change `add w1, w1, w2` to `sub w1, w1, w2`. |
| `loop.elf` | `repeat_add` adds 2 three times and returns 6. | Change `mov w1, #3` to `mov w1, #5` and trace why the loop now totals 10. |
| `calls.elf` | `boost_score` calls `score_bonus` to double a score, then adds 1. | Follow the direct call to the helper. Change the caller's `add w0, w0, #1` to `add w0, w0, #4`. |
| `strings.elf` | `label_address` returns the address of `Mint practice label` in `.rodata`. | Find the label in Strings and follow its cross-reference to the address-loading instruction. |

From the repository root run `sh examples/learn/build.sh` with Android NDK 28.2.13676358. It uses the macOS SDK location by default. Pass the path to the NDK toolchain's `bin` directory as the first argument for other hosts or SDK layouts. Outputs are checked in under `app/src/main/assets/learn/`.
