// Тесты службы AppRoute (issue #16): командная строка, права, состав файлов, защищённый журнал.

#include "core/PrimarySwitch.h"
#include "core/ServiceSetup.h"
#include "core/Util.h"

#include "Test.h"

#include <sddl.h>

#include <algorithm>
#include <filesystem>
#include <format>

using namespace approute;

namespace {

std::wstring TempDirectory(const wchar_t* tag)
{
    wchar_t base[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH, base);
    return std::format(L"{}approute-{}-{}-{}", base, tag, GetCurrentProcessId(), GetTickCount64());
}

void Touch(const std::wstring& path)
{
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
}

} // namespace

TEST(ServiceCommandLineQuotes)
{
    const auto line = ServiceCommandLine(L"C:\\Program Files\\AppRoute\\approute-routes.exe",
                                         L"C:\\Users\\Some One\\AppData\\Roaming\\AppRoute\\config.json", L"S-1-5-21-1-2-3-1001");
    CHECK(line == L"\"C:\\Program Files\\AppRoute\\approute-routes.exe\" service --config "
                  L"\"C:\\Users\\Some One\\AppData\\Roaming\\AppRoute\\config.json\" --client-sid S-1-5-21-1-2-3-1001");
}

TEST(ServiceSecurityDescriptorValid)
{
    const std::wstring sddl = ServiceSecurityDescriptor(L"S-1-5-21-1-2-3-1001");
    PSECURITY_DESCRIPTOR sd = nullptr;
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr));
    LocalFree(sd);
    // Пользователю — запуск (RP) и остановка (WP), но не изменение настроек и не удаление
    const auto ace = sddl.substr(sddl.rfind(L"(A;;"));
    CHECK(ace.find(L"RP") != std::wstring::npos && ace.find(L"WP") != std::wstring::npos);
    CHECK(ace.find(L"DC") == std::wstring::npos && ace.find(L"SD") == std::wstring::npos &&
          ace.find(L"WD") == std::wstring::npos && ace.find(L"WO") == std::wstring::npos);
}

TEST(AppRouteBinariesFilter)
{
    const std::wstring dir = TempDirectory(L"bins");
    CHECK(CreateDirectoryW(dir.c_str(), nullptr));
    for (const wchar_t* name : {L"approute-routes.exe", L"approute-gui.exe", L"approute-hook64.dll", L"approute-hook32.dll",
                                L"approute-tests.exe", L"approute-routes.exe.old-123", L"other.exe", L"approute-core.lib",
                                L"approute-routes.pdb"}) {
        Touch(dir + L"\\" + name);
    }
    auto files = AppRouteBinaries(dir);
    std::sort(files.begin(), files.end());
    CHECK(files == (std::vector<std::wstring>{L"approute-gui.exe", L"approute-hook32.dll", L"approute-hook64.dll",
                                               L"approute-routes.exe"}));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST(ProtectedLogRejectsUserDirectory)
{
    if (IsProcessElevated()) {
        return;   // проверка рассчитана на обычные права
    }
    // Папку заранее создал обычный пользователь — журнал в неё не пишется
    const std::wstring dir = TempDirectory(L"log");
    CHECK(CreateDirectoryW(dir.c_str(), nullptr));
    const HANDLE h = OpenProtectedLog(dir, L"routes.log");
    CHECK(h == nullptr);
    if (h) {
        CloseHandle(h);
    }
    CHECK(GetFileAttributesW((dir + L"\\routes.log").c_str()) == INVALID_FILE_ATTRIBUTES);
    // Отодвинутая папка и (если удалось создать) новая — убрать
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(std::filesystem::path(dir).parent_path(), ec)) {
        if (e.path().wstring().starts_with(dir)) {
            std::filesystem::remove_all(e.path(), ec);
        }
    }
}

TEST(RouteManagerMutexIsGlobal)
{
    // Один менеджер маршрутов на компьютер: служба работает в сеансе 0
    CHECK(std::wstring_view(kRouteManagerMutex).starts_with(L"Global\\"));
}
