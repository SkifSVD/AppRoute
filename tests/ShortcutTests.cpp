// Тесты ярлыков запуска через AppRoute (issue #13).

#include "core/InstalledApps.h"
#include "core/Shortcuts.h"
#include "core/Util.h"

#include "Test.h"

#include <shellapi.h>

#include <filesystem>
#include <vector>

using namespace approute;

namespace {

Rule MakeRule(std::wstring app)
{
    Rule r;
    r.app = std::move(app);
    r.adapter = L"{0F5E9A5F-88C5-4844-9F4C-2037D5332075}";
    return r;
}

// Разбор строки так же, как её разберёт запущенная программа
std::vector<std::wstring> Split(const std::wstring& commandLine)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW((L"x.exe " + commandLine).c_str(), &argc);
    std::vector<std::wstring> out;
    for (int i = 1; argv && i < argc; ++i) {
        out.emplace_back(argv[i]);
    }
    LocalFree(argv);
    return out;
}

} // namespace

TEST(ShortcutQuoteArgument)
{
    CHECK(QuoteArgument(L"simple") == L"simple");
    CHECK(QuoteArgument(L"") == L"\"\"");
    for (const std::wstring arg : {L"C:\\Program Files\\App\\app.exe", L"a\"b", L"C:\\dir with space\\",
                                   L"tail\\\\", L"\\\"x\\\""}) {
        const auto parsed = Split(QuoteArgument(arg));
        CHECK(parsed.size() == 1 && parsed[0] == arg);
    }
}

TEST(ShortcutForRule)
{
    std::wstring error;
    CHECK(!LaunchShortcutFor(MakeRule(L"telegram.exe"), L"C:\\AR\\approute-gui.exe", L"", &error));
    CHECK(!error.empty());

    const auto s = LaunchShortcutFor(MakeRule(L"C:\\Program Files\\App\\app.exe"), L"C:\\AR\\approute-gui.exe",
                                     DefaultConfigPath(), &error);
    CHECK(s.has_value());
    if (s) {
        CHECK(s->target == L"C:\\AR\\approute-gui.exe");
        CHECK(Split(s->arguments) == std::vector<std::wstring>({L"--run", L"C:\\Program Files\\App\\app.exe"}));
        CHECK(s->workingDirectory == L"C:\\Program Files\\App");
        CHECK(s->iconPath == L"C:\\Program Files\\App\\app.exe");
    }

    // Другой файл правил передаётся ярлыку
    const auto c = LaunchShortcutFor(MakeRule(L"C:\\Apps\\app.exe"), L"gui.exe", L"D:\\my rules.json", &error);
    CHECK(c && Split(c->arguments) ==
                   std::vector<std::wstring>({L"--config", L"D:\\my rules.json", L"--run", L"C:\\Apps\\app.exe"}));
}

TEST(ShortcutFileName)
{
    CHECK(LaunchShortcutFileName(MakeRule(L"C:\\Apps\\Telegram.exe")) == L"Telegram (AppRoute).lnk");
    CHECK(LaunchShortcutFileName(MakeRule(L"C:\\Apps\\tool.EXE")) == L"tool (AppRoute).lnk");
    CHECK(LaunchShortcutFileName(MakeRule(L"C:\\Apps\\a?b.com")) == L"a_b.com (AppRoute).lnk");
}

TEST(ShortcutSaveAndRead)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / L"approute-tests-shortcut";
    fs::create_directories(dir);
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    const std::wstring program = std::wstring(sys) + L"\\notepad.exe";
    const std::wstring lnk = (dir / L"Блокнот (AppRoute).lnk").wstring();

    std::wstring error;
    const auto spec = LaunchShortcutFor(MakeRule(program), L"C:\\AR\\approute-gui.exe", L"", &error);
    CHECK(spec && SaveShortcut(lnk, *spec, &error));
    const auto read = ReadShortcut(lnk);
    CHECK(read.has_value());
    if (read && spec) {
        CHECK(EqualsIgnoreCase(read->target, spec->target));
        CHECK(read->arguments == spec->arguments);
        CHECK(EqualsIgnoreCase(read->workingDirectory, spec->workingDirectory));
        CHECK(EqualsIgnoreCase(read->iconPath, program));
    }
    // Ярлыки AppRoute не попадают в список установленных программ
    CHECK(IsUtilityShortcut(L"Блокнот (AppRoute)", L"C:\\AR\\approute-gui.exe"));

    std::error_code ec;
    fs::remove_all(dir, ec);
}
