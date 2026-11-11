add_executable(approute-config main.cpp)
target_link_libraries(approute-config PRIVATE approute_core)
approute_version_resource(approute-config "AppRoute — правила (командная строка)")
