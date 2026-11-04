# Additional real compiler cases beyond the default DWARF4/5 DWARF32 inputs.
set(_endian_outputs)
foreach(_version IN ITEMS 2 3 4 5)
    foreach(_bits IN ITEMS 32 64)
        if((_bits EQUAL 32 AND _version GREATER_EQUAL 4) OR (_bits EQUAL 64 AND _version EQUAL 2))
            continue() # Existing fixtures; LLVM does not emit DWARF2/DWARF64.
        endif()
        set(_width)
        if(_bits EQUAL 64)
            set(_width -gdwarf64)
        endif()
        set(_out "${CMAKE_CURRENT_BINARY_DIR}/corpus/aarch64-be-dwarf${_version}-${_bits}.so")
        add_custom_command(OUTPUT "${_out}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
            COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -std=c11 -O0 -g -gdwarf-${_version} ${_width}
                -fno-eliminate-unused-debug-types -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld -Wl,--build-id=none
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_out}"
            DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" VERBATIM)
        list(APPEND _endian_outputs "${_out}")
        list(APPEND MINT_BIG_ENDIAN_BINARIES "${_out}")
        add_test(NAME big_endian_dwarf_${_version}_${_bits} COMMAND mint_dwarf_test --real "${_out}")
    endforeach()
endforeach()
foreach(_version IN ITEMS 4 5)
    foreach(_bits IN ITEMS 32 64)
        set(_dir "${CMAKE_CURRENT_BINARY_DIR}/corpus/be-debug-${_version}-${_bits}")
        set(_width)
        if(_bits EQUAL 64)
            set(_width -gdwarf64)
        endif()
        add_custom_command(OUTPUT "${_dir}/stripped.so" "${_dir}/external.debug" "${_dir}/compressed.so" "${_dir}/skeleton.so" "${_dir}/split.dwo"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${_dir}"
            COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -std=c11 -O0 -g -gdwarf-${_version} ${_width}
                -fno-eliminate-unused-debug-types -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld -Wl,--build-id=sha1
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_dir}/full.so"
            COMMAND "${_mint_objcopy}" --only-keep-debug "${_dir}/full.so" "${_dir}/external.debug"
            COMMAND "${_mint_objcopy}" --strip-debug --add-gnu-debuglink=${_dir}/external.debug "${_dir}/full.so" "${_dir}/stripped.so"
            COMMAND "${_mint_objcopy}" --compress-debug-sections=zlib "${_dir}/full.so" "${_dir}/compressed.so"
            COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -std=c11 -O1 -g -gdwarf-${_version} ${_width} -gsplit-dwarf
                -fno-eliminate-unused-debug-types -fPIC -fno-stack-protector -c
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_dir}/split.o"
            COMMAND "${_mint_corpus_clang}" --target=aarch64_be-linux-gnu -nostdlib -shared -fuse-ld=lld -Wl,--build-id=none
                "${_dir}/split.o" -o "${_dir}/skeleton.so"
            DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" VERBATIM)
        list(APPEND _endian_outputs "${_dir}/stripped.so" "${_dir}/external.debug" "${_dir}/compressed.so" "${_dir}/skeleton.so" "${_dir}/split.dwo")
        add_test(NAME big_endian_external_${_version}_${_bits} COMMAND mint_external_debug_test
            "${_dir}/stripped.so" "${_dir}/external.debug" "${_dir}/compressed.so" "${_dir}/skeleton.so" "${_dir}/split.dwo")
    endforeach()
endforeach()
add_custom_target(mint_dwarf_endian_corpus_files DEPENDS ${_endian_outputs})
add_dependencies(mint_big_endian_corpus_files mint_dwarf_endian_corpus_files)
add_dependencies(mint_external_debug_test mint_dwarf_endian_corpus_files)
add_dependencies(mint_dwarf_test mint_dwarf_endian_corpus_files)
