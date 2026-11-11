add_executable(approute-dns main.cpp)
target_link_libraries(approute-dns PRIVATE approute_core)
approute_version_resource(approute-dns "AppRoute — проверка разрешения имён")
