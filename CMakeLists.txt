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

# Все exe и dll обеих разрядностей — в одну папку: launcher ищет hook-DLL и помощников рядом с собой
set(APPROUTE_BIN_DIR ${CMAKE_BINARY_DIR}/bin CACHE PATH "Папка для exe и dll")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${APPROUTE_BIN_DIR})

# x86-сборка (build.ps1 делает её второй): только то, что внедряется в 32-битные процессы
option(APPROUTE_HOOK_ONLY "Собрать только hook-DLL и помощник внедрения" OFF)

# Установщик (#64, build.ps1 -Installer — третьей сборкой): только core и approute-setup с файлами
# из этой папки поставки
set(APPROUTE_SETUP_PAYLOAD "" CACHE PATH "Папка поставки для установщика (пусто — установщик не собирается)")

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/W4> /permissive- /utf-8 $<$<COMPILE_LANGUAGE:CXX>:/EHsc> /Zc:__cplusplus)
    # Предупреждения — ошибки: иначе опечатка в ветке ошибки (ручные CloseHandle, проверки Win32)
    # проходит молча. Отключается ключом -DAPPROUTE_WARNINGS_AS_ERRORS=OFF.
    option(APPROUTE_WARNINGS_AS_ERRORS "Считать предупреждения компилятора ошибками" ON)
    if(APPROUTE_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
endif()

include(cmake/AppRouteVersion.cmake)

add_subdirectory(third_party)
add_subdirectory(src/core)
if(APPROUTE_SETUP_PAYLOAD)
    add_subdirectory(src/tools/setup)
    return()
endif()
add_subdirectory(src/hook)
add_subdirectory(src/tools/inject)
if(APPROUTE_HOOK_ONLY)
    return()
endif()
add_subdirectory(src/tools/routes)
add_subdirectory(src/tools/run)
add_subdirectory(src/tools/dns)
add_subdirectory(src/tools/config)
add_subdirectory(src/gui)

enable_testing()
add_subdirectory(tests)
