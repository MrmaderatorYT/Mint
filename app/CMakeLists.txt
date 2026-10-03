cmake_minimum_required(VERSION 3.22.1)
project(mintcore C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(third_party/capstone.cmake)
include(third_party/lua.cmake)
option(MINT_COMPACT_DEBUG "Keep line-table debug data without full type graphs for disk-limited builds" OFF)
if(MINT_COMPACT_DEBUG)
    add_compile_options($<$<CONFIG:Debug>:-g1>)
    target_compile_options(capstone PRIVATE $<$<CONFIG:Debug>:-g1>)
    target_compile_options(mint_lua PRIVATE $<$<CONFIG:Debug>:-g1>)
endif()

# ZIP/DEX front-end and the native program database use the platform copies of
# zlib and SQLite. Both are system components on Android; host builds resolve
# the equivalent desktop libraries.
find_library(MINT_ZLIB_LIBRARY NAMES z)

# The engine grows by many files per work session; CONFIGURE_DEPENDS makes the
# glob re-run when the directory contents change, so adding a pass never means
# editing this file.
file(GLOB_RECURSE MINT_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/*.c
)
set(MINT_ENGINE_ID_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
include(cmake/analysis_engine_id.cmake)

add_library(mintcore SHARED ${MINT_SOURCES})

target_include_directories(mintcore PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp
        ${MINT_ENGINE_GENERATED_DIR}
)

target_link_libraries(mintcore PRIVATE capstone mint_lua log android ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})

target_compile_options(mintcore PRIVATE
        -Wall
        -Wextra
        -Wno-unused-parameter
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections
        # We parse attacker-controlled files. Keep the cheap hardening on even
        # in release: a malformed ELF must fail an analysis, not the process.
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
)

target_compile_options(mintcore PRIVATE
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-O0>
)

target_link_options(mintcore PRIVATE
        # Play requires 16 KB-page-aligned shared libraries. NDK r28 does this
        # by default; stating it explicitly means an older NDK cannot silently
        # produce an unshippable build.
        -Wl,-z,max-page-size=16384
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,--gc-sections
        # Keep Capstone's symbols out of libmintcore's dynamic table: nothing
        # outside this .so should be able to bind to them.
        -Wl,--exclude-libs,ALL
)
