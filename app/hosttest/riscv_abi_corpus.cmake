set(MINT_RISCV_ABI_BINARIES)
set(MINT_RISCV_ABI_ARGUMENTS)
foreach(_bits IN ITEMS 32 64)
    foreach(_float IN ITEMS soft f d)
        set(_abi "riscv${_bits}")
        if(_bits EQUAL 32)
            set(_clang_abi ilp32)
        else()
            set(_clang_abi lp64)
        endif()
        if(NOT _float STREQUAL soft)
            string(APPEND _abi "${_float}")
            string(APPEND _clang_abi "${_float}")
        endif()
        set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/abi-${_abi}.elf")
        add_custom_command(OUTPUT "${_binary}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
            COMMAND "${_mint_corpus_clang}" --target=riscv${_bits}-unknown-elf -march=rv${_bits}imafd -mabi=${_clang_abi}
                -O2 -g -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -nostdlib -fuse-ld=lld
                -Wl,--no-relax -Wl,-e,mint_abi_named_pair
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/riscv_abi.c" -o "${_binary}"
            DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/riscv_abi.c" "${CMAKE_CURRENT_LIST_FILE}" VERBATIM)
        list(APPEND MINT_RISCV_ABI_BINARIES "${_binary}")
        list(APPEND MINT_RISCV_ABI_ARGUMENTS --real "${_abi}" "${_binary}")
    endforeach()
endforeach()
add_custom_target(mint_riscv_abi_corpus_files DEPENDS ${MINT_RISCV_ABI_BINARIES})
