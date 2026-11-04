set(MINT_AAPCS_AGGREGATE_BINARIES)
foreach(_endian IN ITEMS le be)
    set(_target aarch64-linux-gnu)
    if(_endian STREQUAL be)
        set(_target aarch64_be-linux-gnu)
    endif()
    set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/aapcs-aggregate-${_endian}.elf")
    add_custom_command(OUTPUT "${_binary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=${_target} -O2 -g -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -nostdlib -fuse-ld=lld
            -Wl,-e,mint_be_b3 "${CMAKE_CURRENT_LIST_DIR}/fixtures/aapcs_aggregate.c" -o "${_binary}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/aapcs_aggregate.c" VERBATIM)
    list(APPEND MINT_AAPCS_AGGREGATE_BINARIES "${_binary}")
endforeach()
add_custom_target(mint_aapcs_aggregate_corpus_files DEPENDS ${MINT_AAPCS_AGGREGATE_BINARIES})
