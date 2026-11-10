cmake_minimum_required(VERSION 3.25)

project(AppRoute
    VERSION 0.1.0
    DESCRIPTION "Per-application network interface routing for Windows"
    LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "AppRoute поддерживает только Windows")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Статический CRT: exe/dll не требуют установки VC++ Redistributable
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus)
endif()

add_subdirectory(src/core)
add_subdirectory(src/tools/routes)
