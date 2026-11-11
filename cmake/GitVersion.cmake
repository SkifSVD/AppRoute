# Версия AppRoute (#63) — считается по git при каждой сборке.
#
#   cmake -DSOURCE_DIR=... -DBASE_VERSION=X.Y.Z [-DOVERRIDE=X.Y.Z] -DOUTPUT=.../AppRouteVersion.h -P GitVersion.cmake
#   cmake -DSOURCE_DIR=... -DBASE_VERSION=X.Y.Z [-DOVERRIDE=X.Y.Z] -P GitVersion.cmake     — только напечатать версию
#
# Правило:
# - источник — последний тег выпуска vX.Y.Z, достижимый из HEAD; на самом теге версия = тег;
# - после тега — следующий патч (X.Y.Z+1), сколько бы ни было коммитов: каждая публикация
#   (build.ps1 -Publish) ставит новый тег, иначе номер замирает;
# - минор поднимает строка "+semver: minor" в сообщении коммита после тега, мажор — "+semver: major";
# - тегов нет или BASE_VERSION (project(... VERSION) в CMakeLists.txt) больше — берётся BASE_VERSION:
#   так задаётся первая версия и ручной скачок номера;
# - OVERRIDE — ручная версия (хотфикс, build.ps1 -Version).
# Файл OUTPUT перезаписывается, только если изменился, — иначе всё пересобиралось бы.

set(commit "")
set(dirty "")
set(version "${BASE_VERSION}")

find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=8 HEAD
                    WORKING_DIRECTORY "${SOURCE_DIR}" OUTPUT_VARIABLE commit
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
        set(commit "")
    endif()
endif()

if(commit)
    execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
                    WORKING_DIRECTORY "${SOURCE_DIR}" OUTPUT_VARIABLE changes
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(changes)
        set(dirty "-dirty")
    endif()

    execute_process(COMMAND "${GIT_EXECUTABLE}" describe --tags --abbrev=0 --match "v[0-9]*.[0-9]*.[0-9]*"
                    WORKING_DIRECTORY "${SOURCE_DIR}" OUTPUT_VARIABLE tag
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET RESULT_VARIABLE rc)
    if(rc EQUAL 0 AND tag MATCHES "^v([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
        set(major ${CMAKE_MATCH_1})
        set(minor ${CMAKE_MATCH_2})
        set(patch ${CMAKE_MATCH_3})
        execute_process(COMMAND "${GIT_EXECUTABLE}" rev-list --count "${tag}..HEAD"
                        WORKING_DIRECTORY "${SOURCE_DIR}" OUTPUT_VARIABLE count
                        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        if(count GREATER 0)
            execute_process(COMMAND "${GIT_EXECUTABLE}" log --format=%B "${tag}..HEAD"
                            WORKING_DIRECTORY "${SOURCE_DIR}" OUTPUT_VARIABLE messages ERROR_QUIET)
            if(messages MATCHES "(^|\n)\\+semver: ?major")
                math(EXPR major "${major} + 1")
                set(minor 0)
                set(patch 0)
            elseif(messages MATCHES "(^|\n)\\+semver: ?(minor|feature)")
                math(EXPR minor "${minor} + 1")
                set(patch 0)
            else()
                math(EXPR patch "${patch} + 1")
            endif()
        endif()
        set(fromTag "${major}.${minor}.${patch}")
        if(fromTag VERSION_GREATER BASE_VERSION)
            set(version "${fromTag}")
        endif()
    endif()
endif()

if(OVERRIDE)
    set(version "${OVERRIDE}")
endif()
if(NOT version MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "Версия «${version}» — нужен формат X.Y.Z")
endif()
set(major ${CMAKE_MATCH_1})
set(minor ${CMAKE_MATCH_2})
set(patch ${CMAKE_MATCH_3})

if(NOT OUTPUT)
    execute_process(COMMAND "${CMAKE_COMMAND}" -E echo "${version}")
    return()
endif()

if(commit)
    set(full "${version}+${commit}${dirty}")
else()
    set(full "${version}")
endif()

set(content "// Создаётся при сборке (cmake/GitVersion.cmake) — не редактировать.
#pragma once
#define APPROUTE_VERSION_MAJOR ${major}
#define APPROUTE_VERSION_MINOR ${minor}
#define APPROUTE_VERSION_PATCH ${patch}
#define APPROUTE_VERSION_A \"${version}\"
#define APPROUTE_VERSION_W L\"${version}\"
#define APPROUTE_BUILD_A \"${full}\"
#define APPROUTE_BUILD_W L\"${full}\"
")

if(EXISTS "${OUTPUT}")
    file(READ "${OUTPUT}" old)
else()
    set(old "")
endif()
if(NOT old STREQUAL content)
    file(WRITE "${OUTPUT}" "${content}")
endif()
