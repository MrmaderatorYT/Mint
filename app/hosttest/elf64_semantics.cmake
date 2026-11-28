# Build compiler-produced ELF64 for both analyzed target ABIs. The test below
# compiles the recovered Pseudo-C for the host; the target ELF is never run.
set(MINT_ELF64_SEMANTICS_BINARIES)
foreach(_arch IN ITEMS aarch64 x86_64)
    set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/semantic-score-${_arch}.elf")
    set(_source "${CMAKE_CURRENT_LIST_DIR}/fixtures/elf64_semantic_score.c")
    add_custom_command(OUTPUT "${_binary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=${_arch}-linux-android28
                -O2 -ffreestanding -nostdlib -fuse-ld=lld -Wl,-e,mint_score -Wl,--build-id=none
                "${_source}" -o "${_binary}"
        DEPENDS "${_source}" "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Compile ELF64 semantic score fixture for ${_arch}")
    list(APPEND MINT_ELF64_SEMANTICS_BINARIES "${_binary}")
endforeach()
add_custom_target(mint_elf64_semantics_fixtures DEPENDS ${MINT_ELF64_SEMANTICS_BINARIES})
add_dependencies(mint_elf64_semantics_fixtures mint_headless)
