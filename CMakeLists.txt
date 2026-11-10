cmake_minimum_required(VERSION 3.25)

project(AppRoute
    VERSION 0.1.0
    DESCRIPTION "Per-application network interface routing for Windows"
    LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "AppRoute поддерживает только Windows")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Статический CRT: exe/dll не требуют установки VC++ Redistributable
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Все exe и dll — в одну папку: launcher ищет hook-DLL рядом с собой
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/W4> /permissive- /utf-8 $<$<COMPILE_LANGUAGE:CXX>:/EHsc> /Zc:__cplusplus)
endif()

add_subdirectory(third_party)
add_subdirectory(src/core)
add_subdirectory(src/hook)
add_subdirectory(src/tools/routes)
add_subdirectory(src/tools/run)
add_subdirectory(src/tools/dns)
add_subdirectory(src/tools/config)

enable_testing()
add_subdirectory(tests)
