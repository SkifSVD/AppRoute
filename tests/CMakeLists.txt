add_executable(approute-tests main.cpp)
target_link_libraries(approute-tests PRIVATE approute_core)
add_test(NAME approute-tests COMMAND approute-tests)
