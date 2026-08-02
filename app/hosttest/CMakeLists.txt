cmake_minimum_required(VERSION 3.22.1)
project(mint_hosttest C CXX)

# Host build of the analysis engine. Not shipped — it exists so the loaders,
# lifters and decompiler can be exercised in milliseconds against real Android
# libraries instead of through an emulator install.
#
#   cmake -S core/hosttest -B build/hosttest -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build/hosttest -j
#   ./build/hosttest/mint_probe <file.so>

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

# The engine now lives in the app module; this points at it.
set(CORE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

include(${CORE_DIR}/third_party/capstone.cmake)

find_library(MINT_ZLIB_LIBRARY NAMES z REQUIRED)

# Everything except the JNI layer, which needs a JVM to mean anything.
file(GLOB_RECURSE ENGINE_SOURCES CONFIGURE_DEPENDS
        ${CORE_DIR}/src/main/cpp/mint/*.cpp
)

add_executable(mint_probe
        ${ENGINE_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/probe_main.cpp
)

add_executable(mint_ssa_test
        ${ENGINE_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/ssa_main.cpp
)

add_executable(mint_perf_test
        ${ENGINE_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/perf_main.cpp
)

add_executable(mint_feature_test
        ${ENGINE_SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/feature_main.cpp
)

target_include_directories(mint_probe PRIVATE
        ${CORE_DIR}/src/main/cpp
        ${CMAKE_CURRENT_LIST_DIR}/shim
)

target_include_directories(mint_ssa_test PRIVATE
        ${CORE_DIR}/src/main/cpp
        ${CMAKE_CURRENT_LIST_DIR}/shim
)

target_include_directories(mint_perf_test PRIVATE
        ${CORE_DIR}/src/main/cpp
        ${CMAKE_CURRENT_LIST_DIR}/shim
)

target_include_directories(mint_feature_test PRIVATE
        ${CORE_DIR}/src/main/cpp
        ${CMAKE_CURRENT_LIST_DIR}/shim
)

target_link_libraries(mint_probe PRIVATE capstone ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})
target_link_libraries(mint_ssa_test PRIVATE capstone ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})
target_link_libraries(mint_perf_test PRIVATE capstone ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})
target_link_libraries(mint_feature_test PRIVATE capstone ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})

target_compile_options(mint_probe PRIVATE -Wall -Wextra -Wno-unused-parameter -g)
target_compile_options(mint_ssa_test PRIVATE -Wall -Wextra -Wno-unused-parameter -g)
target_compile_options(mint_perf_test PRIVATE -Wall -Wextra -Wno-unused-parameter -g)
target_compile_options(mint_feature_test PRIVATE -Wall -Wextra -Wno-unused-parameter -g)

# The engine parses hostile input, so the host build is where we want sanitizers
# on by default: a bounds bug found here is a crash never shipped.
option(MINT_HOST_SANITIZE "Build the host probe with ASan and UBSan" ON)
if (MINT_HOST_SANITIZE)
    target_compile_options(mint_probe PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mint_probe PRIVATE -fsanitize=address,undefined)
    target_compile_options(mint_ssa_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mint_ssa_test PRIVATE -fsanitize=address,undefined)
    target_compile_options(mint_perf_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mint_perf_test PRIVATE -fsanitize=address,undefined)
    target_compile_options(mint_feature_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mint_feature_test PRIVATE -fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------- host JNI library
#
# The same JNI sources the app ships, built against the desktop JDK's headers so
# the marshalling can be driven from a real JVM. mint_probe proves the engine but
# never crosses JNI, and the JNI layer is where the sharp edges are: six parallel
# output arrays per call, a local reference per string, and bounds checks that have
# to hold for mismatched array lengths. Untested, those would first execute on a
# user's device.
find_package(JNI)
if (JNI_FOUND)
    file(GLOB_RECURSE JNI_SOURCES CONFIGURE_DEPENDS
            ${CORE_DIR}/src/main/cpp/jni/*.cpp
    )
    add_library(mintcore SHARED ${ENGINE_SOURCES} ${JNI_SOURCES})
    target_include_directories(mintcore PRIVATE
            ${CORE_DIR}/src/main/cpp
            ${CMAKE_CURRENT_LIST_DIR}/shim
            ${JNI_INCLUDE_DIRS}
    )
    target_link_libraries(mintcore PRIVATE capstone ${MINT_ZLIB_LIBRARY} ${CMAKE_DL_LIBS})
    target_compile_options(mintcore PRIVATE -Wall -Wextra -Wno-unused-parameter -g)
    # System.loadLibrary on macOS wants a .dylib; the JVM resolves the bare name.
    set_target_properties(mintcore PROPERTIES SUFFIX ".dylib")
else()
    message(STATUS "JNI not found; skipping the host JNI library")
endif()
