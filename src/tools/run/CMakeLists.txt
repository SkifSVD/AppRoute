add_executable(approute-run main.cpp)
target_link_libraries(approute-run PRIVATE approute_core)
# hook-DLL собирается вместе с launcher'ом и лежит рядом с ним
add_dependencies(approute-run approute_hook approute_inject)
