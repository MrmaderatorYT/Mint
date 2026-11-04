set(MINT_MSVC_RTTI_BINARIES)
foreach(_bits IN ITEMS 32 64)
    if(_bits EQUAL 32)
        set(_target i686-pc-windows-msvc)
    else()
        set(_target x86_64-pc-windows-msvc)
    endif()
    set(_object "${CMAKE_CURRENT_BINARY_DIR}/corpus/msvc-rtti-${_bits}.obj")
    set(_binary "${CMAKE_CURRENT_BINARY_DIR}/corpus/msvc-rtti-${_bits}.exe")
    add_custom_command(OUTPUT "${_binary}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=${_target} -std=c++17 -O1 -frtti -fno-exceptions -ffreestanding -fno-stack-protector
            -c "${CMAKE_CURRENT_LIST_DIR}/fixtures/msvc_rtti.cpp" -o "${_object}"
        COMMAND "${_mint_corpus_toolchain}/bin/lld${CMAKE_EXECUTABLE_SUFFIX}" -flavor link /nodefaultlib /entry:mint_msvc_entry /subsystem:console /out:${_binary} "${_object}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/msvc_rtti.cpp" VERBATIM)
    list(APPEND MINT_MSVC_RTTI_BINARIES "${_binary}")
endforeach()
add_custom_target(mint_msvc_rtti_corpus_files DEPENDS ${MINT_MSVC_RTTI_BINARIES})
