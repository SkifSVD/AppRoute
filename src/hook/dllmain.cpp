#include "Hooks.h"

#include "core/Win.h"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(module);
        approute::hook::Install();
        break;
    case DLL_PROCESS_DETACH:
        // При завершении процесса (reserved != nullptr) снимать перехваты незачем и небезопасно
        if (!reserved) {
            approute::hook::Uninstall();
        }
        break;
    default:
        break;
    }
    return TRUE;
}
