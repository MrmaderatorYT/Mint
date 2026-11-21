# Real compiler-produced PIC switch bytes; never execute the target ELF.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(MINT_X86_SWITCH_BINARIES)
foreach(_optimization IN ITEMS O2 O3)
    set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/x86-pic-switch-${_optimization}.elf")
    add_custom_command(OUTPUT "${_binary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_pic_switch.py"
            "${_mint_corpus_clang}" "${_binary}" "${_optimization}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_pic_switch.py"
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/x86_pic_switch.c"
                "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Native x86-64 PIC signed rel32 switch fixture/${_optimization}")
    list(APPEND MINT_X86_SWITCH_BINARIES "${_binary}")
endforeach()
set(MINT_X86_COPY_ELIDED_BINARY "${CMAKE_CURRENT_BINARY_DIR}/corpus/x86-pic-switch-copy-elided-O2.elf")
add_custom_command(OUTPUT "${MINT_X86_COPY_ELIDED_BINARY}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_pic_switch.py"
        "${_mint_corpus_clang}" "${MINT_X86_COPY_ELIDED_BINARY}" O2 copy-elided
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_pic_switch.py"
            "${CMAKE_CURRENT_LIST_DIR}/fixtures/x86_pic_switch.c"
            "${CMAKE_CURRENT_LIST_FILE}"
    VERBATIM COMMENT "x86-64 PIC switch without a post-guard index copy")
add_custom_target(mint_x86_switch_corpus_files DEPENDS ${MINT_X86_SWITCH_BINARIES} "${MINT_X86_COPY_ELIDED_BINARY}")

set(MINT_X86_TAIL_BINARIES)
foreach(_optimization IN ITEMS O2 O3)
    set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/x86-tail-switch-${_optimization}.elf")
    add_custom_command(OUTPUT "${_binary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_tail_switch.py"
            "${_mint_corpus_clang}" "${_binary}" "${_optimization}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/generate_x86_tail_switch.py"
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/x86_tail_switch.c"
                "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Native x86-64 PIC tail-call switch fixture/${_optimization}")
    list(APPEND MINT_X86_TAIL_BINARIES "${_binary}")
endforeach()
add_custom_target(mint_x86_tail_corpus_files DEPENDS ${MINT_X86_TAIL_BINARIES})
