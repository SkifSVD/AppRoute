# approute-setup — установщик AppRoute (#64). Файлы программы вкладываются ресурсами из папки
# поставки APPROUTE_SETUP_PAYLOAD (build.ps1 -Publish -Installer собирает её и передаёт сюда).

if(NOT IS_DIRECTORY "${APPROUTE_SETUP_PAYLOAD}")
    message(FATAL_ERROR "APPROUTE_SETUP_PAYLOAD: нет папки «${APPROUTE_SETUP_PAYLOAD}»")
endif()
file(GLOB payload LIST_DIRECTORIES false "${APPROUTE_SETUP_PAYLOAD}/*")
list(SORT payload)
if(NOT payload)
    message(FATAL_ERROR "APPROUTE_SETUP_PAYLOAD: папка «${APPROUTE_SETUP_PAYLOAD}» пуста")
endif()

# Ресурс 999 — оглавление «<id> <имя файла>», файлы — RCDATA с номерами от 1000
set(index "")
set(rc "// Создаётся при сборке (src/tools/setup/CMakeLists.txt) — не редактировать.\n#pragma code_page(65001)\n")
set(id 1000)
foreach(file IN LISTS payload)
    get_filename_component(name "${file}" NAME)
    string(APPEND index "${id} ${name}\n")
    string(APPEND rc "${id} RCDATA \"${file}\"\n")
    math(EXPR id "${id} + 1")
endforeach()
set(indexFile ${CMAKE_CURRENT_BINARY_DIR}/payload-index.txt)
file(WRITE ${indexFile} "${index}")
string(APPEND rc "999 RCDATA \"${indexFile}\"\n")
set(payloadRc ${CMAKE_CURRENT_BINARY_DIR}/payload.rc)
file(WRITE ${payloadRc} "${rc}")
set_source_files_properties(${payloadRc} PROPERTIES OBJECT_DEPENDS "${payload};${indexFile}")

add_executable(approute-setup WIN32
    main.cpp
    approute-setup.rc
    approute-setup.manifest
    ${payloadRc}
)
target_link_libraries(approute-setup PRIVATE approute_core comctl32)
approute_version_resource(approute-setup "Установка AppRoute")
