// Тесты пошагового добавления программы (issue #37): список установленных программ, ярлыки,
// история интерфейсов.

#include "core/Config.h"
#include "core/InstalledApps.h"
#include "core/Util.h"

#include "Test.h"

#include <shlobj.h>
#include <shobjidl.h>

#include <filesystem>
#include <format>

using namespace approute;

namespace {

constexpr wchar_t kGuidA[] = L"{0F5E9A5F-88C5-4844-9F4C-2037D5332075}";
constexpr wchar_t kGuidB[] = L"{1A2B3C4D-0000-4844-9F4C-2037D5332075}";

std::wstring SystemExe(const wchar_t* name)
{
    wchar_t dir[MAX_PATH] = {};
    GetSystemDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\" + name;
}

// Ярлык на target во временном каталоге
bool MakeShortcut(const std::wstring& lnk, const std::wstring& target)
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* link = nullptr;
    bool ok = SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)));
    if (ok) {
        IPersistFile* file = nullptr;
        ok = SUCCEEDED(link->SetPath(target.c_str())) && SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&file))) &&
             SUCCEEDED(file->Save(lnk.c_str(), TRUE));
        if (file) {
            file->Release();
        }
        link->Release();
    }
    CoUninitialize();
    return ok;
}

} // namespace

TEST(KnownAdaptersHistory)
{
    Config c;
    RememberAdapter(c, {kGuidA, L"happ-xray", L"Wintun"});
    RememberAdapter(c, {kGuidB, L"vpn", L"TAP"});
    CHECK(c.knownAdapters.size() == 2);
    CHECK(c.knownAdapters[0].id == kGuidB);   // последний выбранный — первым

    // Повторный выбор поднимает наверх и обновляет имя, без дубля; регистр GUID не важен
    std::wstring lower = kGuidA;
    for (auto& ch : lower) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    RememberAdapter(c, {lower, L"happ-new", L"Wintun"});
    CHECK(c.knownAdapters.size() == 2);
    CHECK(c.knownAdapters[0].id == kGuidA);
    CHECK(c.knownAdapters[0].name == L"happ-new");
    CHECK(FindKnownAdapter(c, lower) && FindKnownAdapter(c, lower)->name == L"happ-new");

    RememberAdapter(c, {L"happ-xray", L"не GUID", L""});
    CHECK(c.knownAdapters.size() == 2);

    // Не больше kMaxKnownAdapters
    for (int i = 0; i < 40; ++i) {
        RememberAdapter(c, {std::format(L"{{{:08X}-0000-0000-0000-000000000000}}", i), L"x", L""});
    }
    CHECK(c.knownAdapters.size() == kMaxKnownAdapters);
}

TEST(KnownAdaptersConfigRoundTrip)
{
    Config c;
    RememberAdapter(c, {kGuidA, L"happ-xray", L"Wintun Userspace Tunnel"});
    std::wstring error;
    const auto parsed = ParseConfig(SerializeConfig(c), &error);
    CHECK(parsed && parsed->knownAdapters.size() == 1);
    CHECK(parsed && parsed->knownAdapters[0].name == L"happ-xray");
    CHECK(parsed && parsed->knownAdapters[0].description == L"Wintun Userspace Tunnel");

    // Без истории поле не пишется — конфиг остаётся прежним
    CHECK(SerializeConfig(Config{}).find("knownAdapters") == std::string::npos);

    // Ошибочные записи истории пропускаются, конфиг читается
    const auto messy = ParseConfig(R"({"version":1,"rules":[],"knownAdapters":[1,{"id":"x"},{"id":"{0f5e9a5f-88c5-4844-9f4c-2037d5332075}","name":"a"}]})",
                                   &error);
    CHECK(messy && messy->knownAdapters.size() == 1);
    CHECK(messy && messy->knownAdapters[0].id == kGuidA);
    CHECK(ParseConfig(R"({"version":1,"knownAdapters":"oops"})", &error).has_value());
}

TEST(InstalledAppsUtility)
{
    CHECK(IsUtilityShortcut(L"Uninstall Telegram", L"C:\\Apps\\Telegram\\unins000.exe"));
    CHECK(IsUtilityShortcut(L"Telegram", L"C:\\Apps\\Telegram\\unins000.exe"));
    CHECK(IsUtilityShortcut(L"Удалить Программу", L"C:\\Apps\\p\\remove.exe"));
    CHECK(IsUtilityShortcut(L"Word", L"C:\\Windows\\Installer\\{GUID}\\wordicon.exe"));
    CHECK(IsUtilityShortcut(L"Notepad", L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11\\Notepad.exe"));
    CHECK(!IsUtilityShortcut(L"Telegram", L"C:\\Apps\\Telegram\\Telegram.exe"));
    CHECK(!IsUtilityShortcut(L"Яндекс Браузер", L"C:\\Apps\\Yandex\\browser.exe"));
}

TEST(InstalledAppsMerge)
{
    const auto merged = MergeInstalledApps({
        {L"telegram", L"C:\\Apps\\Telegram\\Telegram.exe"},          // App Paths, позже ярлыка
        {L"Uninstall Telegram", L"C:\\Apps\\Telegram\\unins000.exe"},
        {L"Яндекс", L"C:\\Apps\\Yandex\\browser.exe"},
        {L"Calc", L"C:\\Apps\\calc.exe"},
        {L"Telegram Desktop", L"c:\\apps\\telegram\\telegram.exe"},  // тот же файл
    });
    CHECK(merged.size() == 3);
    CHECK(merged[0].name == L"Calc");
    CHECK(merged[1].name == L"telegram");   // первая запись для файла сохраняется
    CHECK(merged[2].name == L"Яндекс");
}

TEST(InstalledAppsFilter)
{
    const InstalledApp app{L"Telegram Desktop", L"C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"};
    CHECK(MatchesAppFilter(app, L""));
    CHECK(MatchesAppFilter(app, L"  "));
    CHECK(MatchesAppFilter(app, L"tele"));
    CHECK(MatchesAppFilter(app, L"TELEGRAM roaming"));
    CHECK(!MatchesAppFilter(app, L"telegram chrome"));
    CHECK(MatchesAppFilter({L"Яндекс Браузер", L"C:\\b.exe"}, L"браузер"));
}

TEST(ProgramFromShortcut)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / L"approute-tests-lnk";
    fs::create_directories(dir);
    const std::wstring notepad = SystemExe(L"notepad.exe");
    const std::wstring lnk = (dir / L"Блокнот.lnk").wstring();
    const std::wstring textLnk = (dir / L"text.lnk").wstring();
    const std::wstring text = (dir / L"readme.txt").wstring();
    { FILE* f = nullptr; if (_wfopen_s(&f, text.c_str(), L"w") == 0 && f) fclose(f); }

    CHECK(MakeShortcut(lnk, notepad));
    CHECK(MakeShortcut(textLnk, text));

    const auto resolved = ResolveShortcut(lnk);
    CHECK(resolved && EqualsIgnoreCase(*resolved, notepad));
    CHECK(!ResolveShortcut(textLnk));

    std::wstring error;
    const auto viaFile = ProgramFromFile(lnk, &error);
    CHECK(viaFile && EqualsIgnoreCase(*viaFile, notepad));
    CHECK(ProgramFromFile(notepad, &error).has_value());
    CHECK(!ProgramFromFile(textLnk, &error) && !error.empty());
    CHECK(!ProgramFromFile(text, &error));
    CHECK(!ProgramFromFile((dir / L"нет.exe").wstring(), &error));

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST(InstalledAppsEnumerate)
{
    // На любой Windows в меню «Пуск» или App Paths есть программы; все — существующие .exe
    const auto apps = EnumerateInstalledApps();
    CHECK(!apps.empty());
    for (const auto& app : apps) {
        CHECK(!app.name.empty());
        CHECK(GetFileAttributesW(app.path.c_str()) != INVALID_FILE_ATTRIBUTES);
    }
}
