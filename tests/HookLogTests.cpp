// Тесты журнала hook-DLL для запусков из approute-gui (issue #68).

#include "core/Launcher.h"

#include "Test.h"

using namespace approute;

TEST(HookLogFileNameFromProgram)
{
    CHECK(HookLogFileName(L"C:\\Program Files\\Telegram Desktop\\Telegram.exe") == L"Telegram.log");
    CHECK(HookLogFileName(L"C:\\Tools\\curl.EXE") == L"curl.log");
    CHECK(HookLogFileName(L"notepad.exe") == L"notepad.log");
    CHECK(HookLogFileName(L"%LOCALAPPDATA%\\AnthropicClaude\\claude.exe") == L"claude.log");
    CHECK(HookLogFileName(L"Microsoft.WindowsTerminal_8wekyb3d8bbwe!App") ==
          L"Microsoft.WindowsTerminal_8wekyb3d8bbwe_App.log");
    CHECK(HookLogFileName(L"C:\\x\\") == L"app.log");
}

TEST(HookLogDirectoryUnderLocalAppData)
{
    const std::wstring dir = HookLogDirectory();
    CHECK(dir.ends_with(L"\\AppRoute\\logs"));
}
