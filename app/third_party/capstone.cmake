# Capstone 6.0.0-Alpha10, vendored under third_party/capstone (BSD-3-Clause,
# with LLVM-derived decoder tables under Apache-2.0-with-LLVM-exception; see
# third_party/capstone/LICENSES). Attribution is surfaced in the app's
# licences screen.
#
# We deliberately do NOT add_subdirectory() the upstream CMakeLists: it
# unconditionally declares a fuzz_disasm executable plus cstool and test
# targets that we do not ship. Listing the sources ourselves also lets us
# compile only the native architectures exposed by Mint, controlling the
# and a ~20 MB static library.
#
# AArch64, ARM/Thumb, X86 (32/64) and RISC-V (32/64+C) decoders are built.
# Additional decoder provenance is recorded in capstone/NATIVE_DECODERS.md.

set(CS_DIR ${CMAKE_CURRENT_LIST_DIR}/capstone)

add_library(capstone STATIC
        ${CS_DIR}/cs.c
        ${CS_DIR}/Mapping.c
        ${CS_DIR}/MCInst.c
        ${CS_DIR}/MCInstrDesc.c
        ${CS_DIR}/MCInstPrinter.c
        ${CS_DIR}/MCRegisterInfo.c
        ${CS_DIR}/SStream.c
        ${CS_DIR}/utils.c

        ${CS_DIR}/arch/AArch64/AArch64BaseInfo.c
        ${CS_DIR}/arch/AArch64/AArch64Disassembler.c
        ${CS_DIR}/arch/AArch64/AArch64DisassemblerExtension.c
        ${CS_DIR}/arch/AArch64/AArch64InstPrinter.c
        ${CS_DIR}/arch/AArch64/AArch64Mapping.c
        ${CS_DIR}/arch/AArch64/AArch64Module.c

        ${CS_DIR}/arch/ARM/ARMBaseInfo.c
        ${CS_DIR}/arch/ARM/ARMDisassembler.c
        ${CS_DIR}/arch/ARM/ARMDisassemblerExtension.c
        ${CS_DIR}/arch/ARM/ARMInstPrinter.c
        ${CS_DIR}/arch/ARM/ARMMapping.c
        ${CS_DIR}/arch/ARM/ARMModule.c

        ${CS_DIR}/arch/RISCV/RISCVBaseInfo.c
        ${CS_DIR}/arch/RISCV/RISCVDisassembler.c
        ${CS_DIR}/arch/RISCV/RISCVDisassemblerExtension.c
        ${CS_DIR}/arch/RISCV/RISCVInstPrinter.c
        ${CS_DIR}/arch/RISCV/RISCVMapping.c
        ${CS_DIR}/arch/RISCV/RISCVModule.c

        ${CS_DIR}/arch/X86/X86ATTInstPrinter.c
        ${CS_DIR}/arch/X86/X86Disassembler.c
        ${CS_DIR}/arch/X86/X86DisassemblerDecoder.c
        ${CS_DIR}/arch/X86/X86InstPrinterCommon.c
        ${CS_DIR}/arch/X86/X86IntelInstPrinter.c
        ${CS_DIR}/arch/X86/X86Mapping.c
        ${CS_DIR}/arch/X86/X86Module.c
)

set_property(TARGET capstone PROPERTY C_STANDARD 99)

target_include_directories(capstone
        PUBLIC ${CS_DIR}/include
        PRIVATE ${CS_DIR}
)

target_compile_definitions(capstone PRIVATE
        CAPSTONE_HAS_AARCH64
        CAPSTONE_HAS_X86
        CAPSTONE_HAS_ARM
        CAPSTONE_HAS_RISCV
        CAPSTONE_AARCH64_SUPPORT
        CAPSTONE_X86_SUPPORT
        CAPSTONE_ARM_SUPPORT
        CAPSTONE_RISCV_SUPPORT
        CAPSTONE_USE_SYS_DYN_MEM
)

# Upstream is built with -w in some configurations; the LLVM-generated decoders
# produce a lot of noise we are never going to fix in a vendored tree.
target_compile_options(capstone PRIVATE
        -w
        -ffunction-sections
        -fdata-sections
)
