# approute-hook64.dll / approute-hook32.dll — внедряется в процесс и привязывает его сокеты
# к выбранному сетевому интерфейсу.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(APPROUTE_HOOK_NAME approute-hook64)
else()
    set(APPROUTE_HOOK_NAME approute-hook32)
endif()

add_library(approute_hook SHARED
    dllmain.cpp
    AdapterResolver.h AdapterResolver.cpp
    Hooks.h           Hooks.cpp
    ProcessHooks.h    ProcessHooks.cpp
    Log.h             Log.cpp
)
set_target_properties(approute_hook PROPERTIES OUTPUT_NAME ${APPROUTE_HOOK_NAME})
target_link_libraries(approute_hook PRIVATE approute_core minhook mswsock)
