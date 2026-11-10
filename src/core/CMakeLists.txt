add_library(approute_core STATIC
    Win.h
    Util.h          Util.cpp
    NetAdapters.h   NetAdapters.cpp
    Routes.h        Routes.cpp
    RouteManager.h  RouteManager.cpp
    ConflictGuard.h ConflictGuard.cpp
    Process.h       Process.cpp
    DnsResolver.h   DnsResolver.cpp
    Nrpt.h          Nrpt.cpp
    Json.h          Json.cpp
    Config.h        Config.cpp
    Launcher.h      Launcher.cpp
    Policy.h
)

target_include_directories(approute_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_compile_definitions(approute_core PUBLIC
    UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000000)

target_link_libraries(approute_core PUBLIC iphlpapi ws2_32 ole32 dnsapi advapi32 shell32)
