# This first production slice is small enough to rebuild for each test run.
# Use the same NDK selection as the broader native compiler corpus.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(_production_root "${CMAKE_CURRENT_LIST_DIR}/../..")
set(_production_spec "${_production_root}/quality/corpus")
set(_production_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/production")
set(_production_tools
    --clang "${_mint_corpus_clang}"
    --linker "${_mint_corpus_toolchain}/bin/ld.lld${CMAKE_EXECUTABLE_SUFFIX}"
    --strip "${_mint_corpus_toolchain}/bin/llvm-strip${CMAKE_EXECUTABLE_SUFFIX}")

file(READ "${_production_spec}/manifest.json" _production_manifest)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_production_spec}/manifest.json")
string(JSON _production_program_count LENGTH "${_production_manifest}" programs)
string(JSON _production_target_count LENGTH "${_production_manifest}" targets)
math(EXPR _production_last_program "${_production_program_count} - 1")
math(EXPR _production_last_target "${_production_target_count} - 1")
set(_production_binaries)
set(_production_sources)
foreach(_program_index RANGE ${_production_last_program})
    string(JSON _id GET "${_production_manifest}" programs ${_program_index} id)
    string(JSON _source GET "${_production_manifest}" programs ${_program_index} source)
    list(APPEND _production_sources "${_production_root}/${_source}")
    foreach(_target_index RANGE ${_production_last_target})
        string(JSON _arch MEMBER "${_production_manifest}" targets ${_target_index})
        foreach(_variant IN ITEMS debug stripped)
            list(APPEND _production_binaries "${_production_output}/${_id}-${_arch}-${_variant}.elf")
        endforeach()
    endforeach()
endforeach()

add_custom_command(OUTPUT "${_production_output}/manifest.json" ${_production_binaries}
    COMMAND "${Python3_EXECUTABLE}" "${_production_spec}/generate.py" "${_production_output}" ${_production_tools}
    DEPENDS "${_production_spec}/generate.py" "${_production_spec}/manifest.json" ${_production_sources}
            "${_mint_corpus_clang}" "${_mint_corpus_toolchain}/bin/ld.lld${CMAKE_EXECUTABLE_SUFFIX}"
            "${_mint_corpus_toolchain}/bin/llvm-strip${CMAKE_EXECUTABLE_SUFFIX}"
    VERBATIM COMMENT "Generate the production ELF64 corpus and provenance manifest")
add_custom_target(mint_production_corpus_files DEPENDS "${_production_output}/manifest.json" ${_production_binaries})
add_dependencies(mint_headless mint_production_corpus_files)

add_test(NAME production_elf64_corpus
    COMMAND "${Python3_EXECUTABLE}" "${_production_spec}/verify.py" "${_production_output}"
        --headless "$<TARGET_FILE:mint_headless>" ${_production_tools})
set_tests_properties(production_elf64_corpus PROPERTIES TIMEOUT 120)
