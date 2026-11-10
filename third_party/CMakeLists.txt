# MinHook (BSD-2-Clause) — перехват функций для hook-DLL.
# Собираем из исходников напрямую, без собственного CMake MinHook (он ставит install-цели).
set(MINHOOK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/minhook)

if(NOT EXISTS ${MINHOOK_DIR}/include/MinHook.h)
    message(FATAL_ERROR "Нет third_party/minhook. Выполните: git submodule update --init")
endif()

add_library(minhook STATIC
    ${MINHOOK_DIR}/src/buffer.c
    ${MINHOOK_DIR}/src/hook.c
    ${MINHOOK_DIR}/src/trampoline.c
    $<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,${MINHOOK_DIR}/src/hde/hde64.c,${MINHOOK_DIR}/src/hde/hde32.c>
)
target_include_directories(minhook PUBLIC ${MINHOOK_DIR}/include)
if(MSVC)
    target_compile_options(minhook PRIVATE /W3)
endif()
