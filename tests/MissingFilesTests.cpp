// Тесты сообщения «нет файла AppRoute» (issue #72).

#include "core/Launcher.h"

#include "Test.h"

#include <filesystem>
#include <string>

using namespace approute;
namespace fs = std::filesystem;

TEST(MissingFileMessageNamesFileAndQuarantine)
{
    const std::wstring text = MissingAppRouteFileMessage(L"C:\\Apps\\AppRoute\\approute-routes.exe");
    CHECK(text.starts_with(L"Нет файла AppRoute:\nC:\\Apps\\AppRoute\\approute-routes.exe"));
    CHECK(text.find(L"карантин") != std::wstring::npos);
    CHECK(text.find(L"переустановите AppRoute") != std::wstring::npos);
}

TEST(LaunchWithoutHookDllExplainsMissingFile)
{
    // Папка без hook-DLL и помощника — как после карантина: запуск отменяется с понятным текстом
    const fs::path dir = fs::temp_directory_path() / L"approute-tests-missing-files";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);

    wchar_t system[MAX_PATH] = {};
    GetSystemDirectoryW(system, MAX_PATH);
    LaunchRequest request;
    request.commandLine = L"\"" + std::wstring(system) + L"\\PING.EXE\" -n 1 127.0.0.1";
    request.binDir = dir.wstring();
    request.adapterGuid = L"{00000000-0000-0000-0000-000000000000}";
    request.inheritStdHandles = false;
    const LaunchResult result = LaunchWithRule(request);
    CHECK(!result.Ok());
    CHECK(result.message.starts_with(L"Нет файла AppRoute:"));
    CHECK(result.message.find(L"approute-hook64.dll") != std::wstring::npos);
    if (result.process) {
        CloseHandle(result.process);
    }
    fs::remove_all(dir, ec);
}
