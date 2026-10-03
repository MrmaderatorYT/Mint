# Requires corpus.cmake toolchain discovery. All inputs are generated from our
# own source and inspected as bytes; none is executed on the host.
set(_mint_objcopy "${_mint_corpus_toolchain}/bin/llvm-objcopy${CMAKE_EXECUTABLE_SUFFIX}")
set(_mint_debug_dir "${CMAKE_CURRENT_BINARY_DIR}/corpus/debug-loader")
set(_mint_debug_full "${_mint_debug_dir}/full.so")
set(_mint_debug_only "${_mint_debug_dir}/external.debug")
set(_mint_debug_stripped "${_mint_debug_dir}/stripped.so")
set(_mint_debug_compressed "${_mint_debug_dir}/compressed.so")
set(_mint_debug_skeleton "${_mint_debug_dir}/skeleton.so")
set(_mint_debug_dwo "${_mint_debug_dir}/split.dwo")
set(_mint_cxx_groups "${_mint_debug_dir}/cxx-groups.so")
set(_mint_pdb_pe "${_mint_debug_dir}/windows-types.exe")
set(_mint_pdb "${_mint_debug_dir}/windows-types.pdb")
add_custom_command(OUTPUT "${_mint_debug_full}" "${_mint_debug_only}" "${_mint_debug_stripped}" "${_mint_debug_compressed}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_mint_debug_dir}"
    COMMAND "${_mint_corpus_clang}" --target=aarch64-linux-android28 -std=c11 -O1 -g -gdwarf-5
        -fno-eliminate-unused-debug-types -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld -Wl,--build-id=none
        "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_mint_debug_full}"
    COMMAND "${_mint_objcopy}" --only-keep-debug "${_mint_debug_full}" "${_mint_debug_only}"
    COMMAND "${_mint_objcopy}" --strip-debug --add-gnu-debuglink=${_mint_debug_only} "${_mint_debug_full}" "${_mint_debug_stripped}"
    COMMAND "${_mint_objcopy}" --compress-debug-sections=zlib "${_mint_debug_full}" "${_mint_debug_compressed}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" "${CMAKE_CURRENT_LIST_FILE}" VERBATIM)
add_custom_command(OUTPUT "${_mint_debug_skeleton}" "${_mint_debug_dwo}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_mint_debug_dir}"
    COMMAND "${_mint_corpus_clang}" --target=aarch64-linux-android28 -std=c11 -O1 -g -gdwarf-5 -gsplit-dwarf
        -fno-eliminate-unused-debug-types -fPIC -fno-stack-protector -c
        "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_mint_debug_dir}/split.o"
    COMMAND "${_mint_corpus_clang}" --target=aarch64-linux-android28 -nostdlib -shared -fuse-ld=lld -Wl,--build-id=none
        "${_mint_debug_dir}/split.o" -o "${_mint_debug_skeleton}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" "${CMAKE_CURRENT_LIST_FILE}" VERBATIM)
add_custom_command(OUTPUT "${_mint_cxx_groups}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_mint_debug_dir}"
    COMMAND "${_mint_corpus_clang}" --target=aarch64-linux-android28 -std=c++17 -O1 -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld
        "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_metadata.cpp" -o "${_mint_cxx_groups}"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_metadata.cpp" "${CMAKE_CURRENT_LIST_FILE}" VERBATIM)
set(MINT_DEBUG_LOADER_BINARIES "${_mint_debug_stripped}" "${_mint_debug_only}" "${_mint_debug_compressed}" "${_mint_debug_skeleton}" "${_mint_debug_dwo}")
set(MINT_CXX_GROUP_FIXTURE "${_mint_cxx_groups}")
add_custom_command(OUTPUT "${_mint_pdb_pe}" "${_mint_pdb}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_mint_debug_dir}"
    COMMAND "${_mint_corpus_clang}" --target=x86_64-pc-windows-msvc -std=c11 -O0 -g -gcodeview -fno-stack-protector
        -c "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_mint_debug_dir}/windows-types.obj"
    COMMAND "${_mint_corpus_toolchain}/bin/lld${CMAKE_EXECUTABLE_SUFFIX}" -flavor link /debug:full /nodefaultlib
        /entry:mint_debug_entry /subsystem:console /pdb:${_mint_pdb} /out:${_mint_pdb_pe} "${_mint_debug_dir}/windows-types.obj"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" "${CMAKE_CURRENT_LIST_FILE}" VERBATIM)
set(MINT_PDB_BINARIES "${_mint_pdb_pe}" "${_mint_pdb}")
add_custom_target(mint_debug_loader_corpus_files DEPENDS ${MINT_DEBUG_LOADER_BINARIES} "${MINT_CXX_GROUP_FIXTURE}" ${MINT_PDB_BINARIES})
