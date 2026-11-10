add_library(approute_core STATIC
    Win.h
    Util.h          Util.cpp
    NetAdapters.h   NetAdapters.cpp
    Routes.h        Routes.cpp
    RouteManager.h  RouteManager.cpp
    Process.h       Process.cpp
)

target_include_directories(approute_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_compile_definitions(approute_core PUBLIC
    UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000000)

target_link_libraries(approute_core PUBLIC iphlpapi ws2_32 ole32)
