# Версия AppRoute (#63) — по тегам выпусков git, правило — в cmake/GitVersion.cmake.
# project(AppRoute VERSION ...) в корневом CMakeLists.txt — базовая версия: первая (пока тегов
# нет) и ручной скачок номера. APPROUTE_VERSION_OVERRIDE — ручная версия (build.ps1 -Version).
# При каждой сборке approute_version создаёт generated/AppRouteVersion.h; approute_version_resource
# добавляет цели ресурс VERSIONINFO.

set(APPROUTE_VERSION_OVERRIDE "" CACHE STRING "Ручная версия X.Y.Z вместо вычисленной по тегам")
set(APPROUTE_GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${APPROUTE_GENERATED_DIR})

add_custom_target(approute_version
    COMMAND ${CMAKE_COMMAND}
        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DBASE_VERSION=${PROJECT_VERSION}
        -DOVERRIDE=${APPROUTE_VERSION_OVERRIDE}
        -DOUTPUT=${APPROUTE_GENERATED_DIR}/AppRouteVersion.h
        -P ${CMAKE_CURRENT_LIST_DIR}/GitVersion.cmake
    BYPRODUCTS ${APPROUTE_GENERATED_DIR}/AppRouteVersion.h
    COMMENT "Версия AppRoute"
    VERBATIM)

# approute_version_resource(<цель> "<описание>") — ресурс версии с именем файла цели
function(approute_version_resource target description)
    get_target_property(type ${target} TYPE)
    get_target_property(name ${target} OUTPUT_NAME)
    if(NOT name)
        set(name ${target})
    endif()
    if(type STREQUAL "SHARED_LIBRARY")
        set(APPROUTE_RC_FILETYPE "VFT_DLL")
        set(APPROUTE_RC_FILENAME "${name}.dll")
    else()
        set(APPROUTE_RC_FILETYPE "VFT_APP")
        set(APPROUTE_RC_FILENAME "${name}.exe")
    endif()
    set(APPROUTE_RC_NAME ${name})
    set(APPROUTE_RC_DESCRIPTION ${description})
    set(rc ${CMAKE_CURRENT_BINARY_DIR}/${target}_version.rc)
    configure_file(${CMAKE_SOURCE_DIR}/cmake/version.rc.in ${rc} @ONLY)
    target_sources(${target} PRIVATE ${rc})
    set_property(SOURCE ${rc} APPEND PROPERTY INCLUDE_DIRECTORIES ${APPROUTE_GENERATED_DIR})
    add_dependencies(${target} approute_version)
endfunction()
