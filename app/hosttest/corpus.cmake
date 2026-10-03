# Included by the host harness when a reproducible native compiler corpus is
# desired. Root CMakeLists owns mint_tool/test registration; this file only owns
# fixture generation. No input executable is ever launched.
set(MINT_CORPUS_NDK "" CACHE PATH "Android NDK root for the seven-ISA native corpus")
if(NOT MINT_CORPUS_NDK)
    file(GLOB _mint_corpus_ndks "$ENV{HOME}/Library/Android/sdk/ndk/*")
    list(SORT _mint_corpus_ndks COMPARE NATURAL ORDER DESCENDING)
    foreach(_ndk IN LISTS _mint_corpus_ndks)
        if(EXISTS "${_ndk}/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang")
            set(MINT_CORPUS_NDK "${_ndk}" CACHE PATH "Android NDK root for the seven-ISA native corpus" FORCE)
            break()
        endif()
    endforeach()
endif()
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    set(_mint_corpus_host darwin-x86_64)
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(_mint_corpus_host linux-x86_64)
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    set(_mint_corpus_host windows-x86_64)
endif()
set(_mint_corpus_toolchain "${MINT_CORPUS_NDK}/toolchains/llvm/prebuilt/${_mint_corpus_host}")
set(_mint_corpus_clang "${_mint_corpus_toolchain}/bin/clang${CMAKE_EXECUTABLE_SUFFIX}")
if(NOT EXISTS "${_mint_corpus_clang}")
    message(FATAL_ERROR "Native corpus requires an NDK clang; configure -DMINT_CORPUS_NDK=/path/to/ndk")
endif()
set(MINT_CORPUS_BINARIES)
foreach(_isa IN ITEMS aarch64 x86_64 arm thumb x86_32 riscv32 riscv64)
    set(_extra)
    if(_isa STREQUAL aarch64)
        set(_target aarch64-linux-android28)
    elseif(_isa STREQUAL x86_64)
        set(_target x86_64-linux-android28)
    elseif(_isa STREQUAL arm OR _isa STREQUAL thumb)
        set(_target armv7a-linux-androideabi28)
        if(_isa STREQUAL thumb)
            set(_extra -mthumb)
        else()
            set(_extra -marm)
        endif()
    elseif(_isa STREQUAL x86_32)
        set(_target i686-linux-android28)
    elseif(_isa STREQUAL riscv32)
        set(_target riscv32-unknown-elf)
        set(_extra -march=rv32imac -mabi=ilp32 -mno-relax -Wl,--no-relax)
    else()
        set(_target riscv64-unknown-elf)
        set(_extra -march=rv64imac -mabi=lp64 -mno-relax -Wl,--no-relax)
    endif()
    foreach(_optimization IN ITEMS O0 O1 O2 O3 Os Oz O2lto)
        set(_optimization_flags -${_optimization})
        if(_optimization STREQUAL O2lto)
            set(_optimization_flags -O2 -flto)
        endif()
        set(_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/${_isa}-${_optimization}.elf")
        add_custom_command(OUTPUT "${_output}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
            COMMAND "${_mint_corpus_clang}" --target=${_target} ${_extra}
                -std=c11 ${_optimization_flags} -g -gdwarf-4 -ffreestanding -fno-builtin -fno-inline
                -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
                -fno-pic -fno-pie -nostdlib -static -fuse-ld=lld
                -Wl,-e,corpus_entry -Wl,--image-base=0x10000 -Wl,--build-id=none
                "${CMAKE_CURRENT_LIST_DIR}/fixtures/corpus_native.c" -o "${_output}"
            DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/corpus_native.c"
                    "${CMAKE_CURRENT_LIST_FILE}"
            VERBATIM COMMENT "Native corpus ${_isa}/${_optimization}")
        list(APPEND MINT_CORPUS_BINARIES "${_output}")
    endforeach()
endforeach()
add_custom_target(mint_native_corpus_files DEPENDS ${MINT_CORPUS_BINARIES})

# Small real debug-info libraries exercise DWARF4 and DWARF5 through the same
# Session/Program path as an imported native library. They require neither a
# host execution environment nor copied NDK runtimes.
set(MINT_DWARF_BINARIES)
foreach(_isa IN ITEMS aarch64 x86_64)
    if(_isa STREQUAL aarch64)
        set(_target aarch64-linux-android28)
        set(_dwarf_version 5)
    else()
        set(_target x86_64-linux-android28)
        set(_dwarf_version 4)
    endif()
    set(_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/${_isa}-dwarf${_dwarf_version}.so")
    add_custom_command(OUTPUT "${_output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=${_target}
            -std=c11 -O0 -g -gdwarf-${_dwarf_version} -fno-eliminate-unused-debug-types
            -fPIC -fno-stack-protector -nostdlib -shared -fuse-ld=lld
            -Wl,--build-id=none
            "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c" -o "${_output}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/dwarf_fixture.c"
                "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Native DWARF corpus ${_isa}/DWARF${_dwarf_version}")
    list(APPEND MINT_DWARF_BINARIES "${_output}")
endforeach()
add_custom_target(mint_dwarf_corpus_files DEPENDS ${MINT_DWARF_BINARIES})

# Retain unresolved __cxa/personality imports in tiny shared ELF fixtures. The
# header and local symbol table are deliberately omitted: unwind/LSDA readers
# must inspect .eh_frame rather than rely on .eh_frame_hdr or a function name.
# Dynamic imports/exports and allocated unwind tables remain available. These
# are metadata-only inputs.
set(MINT_EXCEPTION_BINARIES)
foreach(_isa IN ITEMS aarch64 x86_64 x86_32)
    if(_isa STREQUAL aarch64)
        set(_target aarch64-linux-android28)
    elseif(_isa STREQUAL x86_64)
        set(_target x86_64-linux-android28)
    else()
        set(_target i686-linux-android28)
    endif()
    set(_output "${CMAKE_CURRENT_BINARY_DIR}/corpus/${_isa}-exceptions.so")
    add_custom_command(OUTPUT "${_output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/corpus"
        COMMAND "${_mint_corpus_clang}" --target=${_target}
            -std=c++17 -O1 -g -gdwarf-4 -fPIC -fexceptions -frtti -funwind-tables
            -fno-stack-protector -nostdlib -shared -fuse-ld=lld
            -Wl,--no-eh-frame-hdr -Wl,--strip-all -Wl,--build-id=none
            "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_exceptions.cpp" -o "${_output}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/fixtures/cxx_exceptions.cpp"
                "${CMAKE_CURRENT_LIST_FILE}"
        VERBATIM COMMENT "Native C++ exception corpus ${_isa}")
    list(APPEND MINT_EXCEPTION_BINARIES "${_output}")
endforeach()
add_custom_target(mint_exception_corpus_files DEPENDS ${MINT_EXCEPTION_BINARIES})

set(MINT_CORPUS_LIBRARIES)
foreach(_abi IN ITEMS aarch64-linux-android x86_64-linux-android)
    set(_library "${_mint_corpus_toolchain}/sysroot/usr/lib/${_abi}/libc++_shared.so")
    if(EXISTS "${_library}")
        list(APPEND MINT_CORPUS_LIBRARIES --library "${_library}")
    endif()
endforeach()
# Host harness hook:
# include(${CMAKE_CURRENT_LIST_DIR}/corpus.cmake)
# mint_tool(mint_corpus_test corpus_main.cpp)
# add_dependencies(mint_corpus_test mint_native_corpus_files)
# add_test(NAME native_compiler_corpus COMMAND mint_corpus_test
#          ${MINT_CORPUS_BINARIES} ${MINT_CORPUS_LIBRARIES})
# add_dependencies(mint_platform_extensions_test mint_dwarf_corpus_files)
# add_test(NAME real_dwarf_corpus COMMAND mint_platform_extensions_test
#          ${MINT_DWARF_BINARIES})
# add_dependencies(mint_exception_metadata_test mint_exception_corpus_files)
# add_test(NAME real_exception_corpus COMMAND mint_exception_metadata_test
#          ${MINT_EXCEPTION_BINARIES})
