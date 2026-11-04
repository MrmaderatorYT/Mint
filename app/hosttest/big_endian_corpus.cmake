# Reuses the explicitly configured corpus NDK; never executes target code.
set(MINT_BIG_ENDIAN_BINARIES)
foreach(_version IN ITEMS 4 5)
    set(_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-dwarf${_version}.so")
    add_custom_command(OUTPUT "${_output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu
            -std=c11 -O0 -g -gdwarf-${_version} -fno-eliminate-unused-debug-types
            -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld -Wl,--build-id=none
            "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_output}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Big-endian AArch64 DWARF${_version}")
    list(APPEND MINT_BIG_ENDIAN_BINARIES "${_output}")
endforeach()
foreach(_compression IN ITEMS zlib)
    set(_compressed "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-${_compression}.so")
    add_custom_command(OUTPUT "${_compressed}"
        COMMAND "${_mint_corpus_toolchain}/bin/llvm-objcopy${CMAKE_EXECUTABLE_SUFFIX}"
            --compress-debug-sections=${_compression} "${_output}" "${_compressed}"
        DEPENDS "${_output}" VERBATIM COMMENT "Big-endian compressed DWARF ${_compression}")
    list(APPEND MINT_BIG_ENDIAN_BINARIES "${_compressed}")
endforeach()
set(MINT_BIG_ENDIAN_CXX "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-cxx.so")
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(_gnu_source "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-dwarf5.so")
set(_gnu_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-gnu.so")
set(_gnu_raw "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-debug-info.bin")
set(_gnu_payload "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-debug-info.zlib")
add_custom_command(OUTPUT "${_gnu_output}"
    COMMAND "${_mint_corpus_toolchain}/bin/llvm-objcopy${CMAKE_EXECUTABLE_SUFFIX}"
        --dump-section .debug_info=${_gnu_raw} "${_gnu_source}" "${_gnu_output}.dump"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_LIST_DIR}/compress_debug_section.py" "${_gnu_raw}" "${_gnu_payload}"
    COMMAND "${_mint_corpus_toolchain}/bin/llvm-objcopy${CMAKE_EXECUTABLE_SUFFIX}"
        --update-section .debug_info=${_gnu_payload} "${_gnu_source}" "${_gnu_output}.intermediate"
    COMMAND "${_mint_corpus_toolchain}/bin/llvm-objcopy${CMAKE_EXECUTABLE_SUFFIX}"
        --rename-section .debug_info=.zdebug_info "${_gnu_output}.intermediate" "${_gnu_output}"
    DEPENDS "${_gnu_source}" "${CMAKE_CURRENT_LIST_DIR}/compress_debug_section.py" VERBATIM)
list(APPEND MINT_BIG_ENDIAN_BINARIES "${_gnu_output}")
set(MINT_BIG_ENDIAN_EXCEPTIONS "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-exceptions.so")
add_custom_command(OUTPUT "${MINT_BIG_ENDIAN_CXX}"
    COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -std=c++17 -O1 -g -gdwarf-5
        -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld
        "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_metadata.cpp" -o "${MINT_BIG_ENDIAN_CXX}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_metadata.cpp" VERBATIM)
add_custom_command(OUTPUT "${MINT_BIG_ENDIAN_EXCEPTIONS}"
    COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -std=c++17 -O1 -g -gdwarf-4
        -fPIC -fexceptions -frtti -funwind-tables -fno-stack-protector -nostdlib -shared -fuse-ld=lld
        -Wl,--no-eh-frame-hdr -Wl,--strip-all -Wl,--build-id=none
        "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_exceptions.cpp" -o "${MINT_BIG_ENDIAN_EXCEPTIONS}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_exceptions.cpp" VERBATIM)
add_custom_target(mint_big_endian_corpus_files DEPENDS ${MINT_BIG_ENDIAN_BINARIES} "${MINT_BIG_ENDIAN_CXX}" "${MINT_BIG_ENDIAN_EXCEPTIONS}")
add_dependencies(mint_big_endian_test mint_big_endian_corpus_files)

add_dependencies(mint_cxx_metadata_test mint_big_endian_corpus_files)
add_dependencies(mint_exception_metadata_test mint_big_endian_corpus_files)
