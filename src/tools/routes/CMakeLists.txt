add_executable(approute-routes main.cpp)
target_link_libraries(approute-routes PRIVATE approute_core)
approute_version_resource(approute-routes "AppRoute — менеджер маршрутов и служба")
