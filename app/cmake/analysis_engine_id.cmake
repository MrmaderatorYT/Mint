# Cache compatibility follows the actual native implementation, including local
# uncommitted edits, rather than a developer remembering to bump a version.
file(GLOB_RECURSE MINT_ENGINE_ID_INPUTS CONFIGURE_DEPENDS
    "${MINT_ENGINE_ID_ROOT}/src/main/cpp/mint/*.cpp"
    "${MINT_ENGINE_ID_ROOT}/src/main/cpp/mint/*.h"
    "${MINT_ENGINE_ID_ROOT}/third_party/capstone/*.h"
    "${MINT_ENGINE_ID_ROOT}/third_party/capstone/*.c"
    "${MINT_ENGINE_ID_ROOT}/third_party/capstone/*.inc")
list(SORT MINT_ENGINE_ID_INPUTS)
set(MINT_ENGINE_ID_CONTENT "mint-derived-analysis-contract-1\n")
foreach(MINT_ENGINE_ID_INPUT IN LISTS MINT_ENGINE_ID_INPUTS)
    file(SHA256 "${MINT_ENGINE_ID_INPUT}" MINT_ENGINE_ID_FILE_HASH)
    file(RELATIVE_PATH MINT_ENGINE_ID_RELATIVE "${MINT_ENGINE_ID_ROOT}" "${MINT_ENGINE_ID_INPUT}")
    string(APPEND MINT_ENGINE_ID_CONTENT "${MINT_ENGINE_ID_RELATIVE}:${MINT_ENGINE_ID_FILE_HASH}\n")
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${MINT_ENGINE_ID_INPUTS})
string(SHA256 MINT_ANALYSIS_ENGINE_ID "${MINT_ENGINE_ID_CONTENT}")
set(MINT_ENGINE_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file("${MINT_ENGINE_ID_ROOT}/cmake/analysis_engine_id.h.in"
    "${MINT_ENGINE_GENERATED_DIR}/mint_analysis_engine_id.h" @ONLY)
