execute_process(COMMAND "${TOOL}" --emit-c "${TEMP_ROOT}/tail-call-runtime.c"
    RESULT_VARIABLE generated OUTPUT_VARIABLE generation_out ERROR_VARIABLE generation_error)
if(NOT generated EQUAL 0)
    message(FATAL_ERROR "Tail C generation failed: ${generation_out}\n${generation_error}")
endif()
execute_process(COMMAND "${COMPILER}" -std=c11 -DMINT_TAIL_GENERATED_MAIN
    -fsanitize=undefined -fno-omit-frame-pointer "${TEMP_ROOT}/tail-call-runtime.c"
    -o "${TEMP_ROOT}/tail-call-runtime"
    RESULT_VARIABLE compiled OUTPUT_VARIABLE compile_out ERROR_VARIABLE compile_error)
if(NOT compiled EQUAL 0)
    message(FATAL_ERROR "Tail C compilation failed: ${compile_out}\n${compile_error}")
endif()
execute_process(COMMAND "${TEMP_ROOT}/tail-call-runtime"
    RESULT_VARIABLE executed OUTPUT_VARIABLE runtime_out ERROR_VARIABLE runtime_error)
if(NOT executed EQUAL 0)
    message(FATAL_ERROR "Tail C semantics failed: ${runtime_out}\n${runtime_error}")
endif()
