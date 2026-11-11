// Тесты предупреждения «программа уже запущена без AppRoute» (issue #70).

#include "core/Launcher.h"

#include "Test.h"

#include <algorithm>
#include <string>

using namespace approute;

namespace {

std::wstring SystemExe(const wchar_t* name)
{
    wchar_t dir[MAX_PATH] = {};
    GetSystemDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\" + name;
}

bool Contains(const std::vector<DWORD>& pids, DWORD pid)
{
    return std::find(pids.begin(), pids.end(), pid) != pids.end();
}

} // namespace

TEST(ImageRunsWithoutRuleFindsPlainProcess)
{
    // ping.exe, запущенный обычным способом (без hook-DLL), — «уже работающая копия без правила».
    // Если сами тесты запущены из программы под AppRoute (с дочерними процессами), ping тоже
    // получит hook-DLL — проверка «без правила» тогда не имеет смысла.
    if (GetModuleHandleW(L"approute-hook64.dll") || GetModuleHandleW(L"approute-hook32.dll")) {
        std::printf("  (пропуск: тесты запущены под AppRoute — дочерние процессы получают hook-DLL)\n");
        return;
    }
    const std::wstring ping = SystemExe(L"PING.EXE");
    std::wstring cmd = L"\"" + ping + L"\" -n 30 127.0.0.1";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    CHECK(CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));
    if (!pi.hProcess) {
        return;
    }
    Sleep(300);   // модули загружены

    CHECK(Contains(ImageRunsWithoutRule(ping, 0), pi.dwProcessId));
    CHECK(!Contains(ImageRunsWithoutRule(ping, pi.dwProcessId), pi.dwProcessId));   // сам запущенный — не в счёт
    CHECK(!Contains(ImageRunsWithoutRule(SystemExe(L"where.exe"), 0), pi.dwProcessId));   // другой exe
    CHECK(ImageRunsWithoutRule(L"", 0).empty());

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

TEST(AlreadyRunningWarningNamesProgram)
{
    const std::wstring text = AlreadyRunningWarning(L"C:\\Program Files\\App\\browser.exe", 3);
    CHECK(text.starts_with(L"browser.exe уже была запущена без AppRoute (процессов: 3)"));
    CHECK(text.find(L"Закройте программу полностью") != std::wstring::npos);
}
