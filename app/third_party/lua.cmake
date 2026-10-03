# Lua 5.5.1, official upstream archive. Compiled as C++ so Lua's protected
# errors unwind C++ callback temporaries instead of longjmp across destructors.
set(MINT_LUA_DIR ${CMAKE_CURRENT_LIST_DIR}/lua-5.5.1/src)
set(MINT_LUA_FILES lapi lcode lctype ldebug ldo ldump lfunc lgc llex lmem
    lobject lopcodes lparser lstate lstring ltable ltm lundump lvm lzio
    lauxlib lbaselib lmathlib lstrlib ltablib lutf8lib)
set(MINT_LUA_SOURCES)
foreach(part ${MINT_LUA_FILES})
    list(APPEND MINT_LUA_SOURCES ${MINT_LUA_DIR}/${part}.c)
endforeach()
set_source_files_properties(${MINT_LUA_SOURCES} PROPERTIES LANGUAGE CXX)
add_library(mint_lua STATIC ${MINT_LUA_SOURCES})
set_target_properties(mint_lua PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(mint_lua PUBLIC ${MINT_LUA_DIR})
target_compile_options(mint_lua PRIVATE -fvisibility=hidden)
