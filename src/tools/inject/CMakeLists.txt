# approute-inject64.exe / approute-inject32.exe — помощник для внедрения в процессы другой разрядности.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(APPROUTE_INJECT_NAME approute-inject64)
else()
    set(APPROUTE_INJECT_NAME approute-inject32)
endif()

add_executable(approute_inject main.cpp)
set_target_properties(approute_inject PROPERTIES OUTPUT_NAME ${APPROUTE_INJECT_NAME})
target_link_libraries(approute_inject PRIVATE approute_core)
