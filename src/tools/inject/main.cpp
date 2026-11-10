// approute-inject32.exe / approute-inject64.exe — вспомогательный инжектор AppRoute (issue #7).
//
//   approute-inject32 --handle <hex> --dll <путь> [--timeout <мс>]
//
// Нужен, когда разрядность процесса отличается от разрядности того, кто его запустил
// (64-битный approute-run → 32-битная программа, 32-битная программа → 64-битный дочерний
// процесс): LoadLibraryW удалённым потоком надёжно вызывается только из процесса той же
// разрядности.
//
// Границы (см. SECURITY.md): помощник не открывает процессы сам — работает только с
// описателем, который ему передал (унаследовал) вызывающий, поэтому не получает прав сверх
// вызывающего; внедряет только hook-DLL AppRoute из своей папки; соблюдает те же запреты,
// что и остальной AppRoute (защитное/системное ПО, процессы других пользователей).
// Код выхода — код ошибки Win32 (0 — успех).

#include "core/Process.h"
#include "core/Util.h"

#include <cwchar>
#include <string>
#include <string_view>

using namespace approute;

int wmain(int argc, wchar_t** argv)
{
    HANDLE process = nullptr;
    std::wstring dll;
    DWORD timeoutMs = 15000;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring_view arg = argv[i];
        if (arg == L"--handle") {
            process = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(std::wcstoull(argv[i + 1], nullptr, 16)));
        } else if (arg == L"--dll") {
            dll = argv[i + 1];
        } else if (arg == L"--timeout") {
            timeoutMs = std::wcstoul(argv[i + 1], nullptr, 10);
        } else {
            return ERROR_INVALID_PARAMETER;
        }
    }
    if (!process || dll.empty() || GetProcessId(process) == 0) {
        return ERROR_INVALID_HANDLE;
    }

    // Только hook-DLL AppRoute из папки помощника, нужной разрядности
    const std::wstring dir = ModuleDirectory(reinterpret_cast<const void*>(&wmain));
    constexpr bool self32 = sizeof(void*) == 4;
    if (!EqualsIgnoreCase(dll, HookDllPath(dir, self32))) {
        return ERROR_ACCESS_DENIED;
    }
    if (IsProcessWow64(process) != self32) {
        return ERROR_BAD_EXE_FORMAT;
    }

    // Те же защитные границы, что у approute-run и hook-DLL
    const std::wstring image = GetProcessImageName(process);
    if (image.empty() || IsProtectedExecutable(image) || IsAppRouteHelper(image) ||
        !ProcessUserMatchesCurrent(process)) {
        return ERROR_ACCESS_DENIED;
    }
    return static_cast<int>(InjectDll(process, dll, timeoutMs));
}
