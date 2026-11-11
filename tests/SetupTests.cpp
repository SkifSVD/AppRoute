// Тесты установщика (issue #64): установка, обновление с резервной копией, откат, удаление.

#include "core/Setup.h"
#include "core/Util.h"

#include "Test.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace approute;
namespace fs = std::filesystem;

namespace {

// Файлы «версии»: содержимое — метка версии, чтобы видеть, какая версия лежит в папке
struct Payload {
    std::string gui;
    std::string hook;
    std::vector<PayloadFile> files;

    explicit Payload(const std::string& version) : gui("gui " + version), hook("hook " + version)
    {
        files.push_back({L"approute-gui.exe", std::as_bytes(std::span(gui.data(), gui.size()))});
        files.push_back({L"approute-hook64.dll", std::as_bytes(std::span(hook.data(), hook.size()))});
    }
};

std::string ReadText(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

fs::path FreshDir(const wchar_t* name)
{
    const fs::path dir = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(dir, ec);
    return dir;
}

bool Install(const fs::path& dir, const std::string& version, SetupReport* report = nullptr)
{
    Payload p(version);
    const std::string setup = "setup " + version;
    SetupReport local;
    return InstallFiles(dir.wstring(), p.files, std::wstring(version.begin(), version.end()),
                        std::as_bytes(std::span(setup.data(), setup.size())), report ? report : &local);
}

} // namespace

TEST(CompareVersionsOrdersNumerically)
{
    CHECK(CompareVersions(L"0.1.0", L"0.1.0") == 0);
    CHECK(CompareVersions(L"0.1.0", L"0.1.1") < 0);
    CHECK(CompareVersions(L"0.10.0", L"0.9.9") > 0);
    CHECK(CompareVersions(L"1.0", L"1.0.0") == 0);
    CHECK(CompareVersions(L"2.0.0", L"10.0.0") < 0);
}

TEST(InspectInstallDirectoryStates)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-inspect");
    CHECK(InspectInstallDirectory(dir.wstring()) == InstallDirState::Missing);
    fs::create_directories(dir);
    CHECK(InspectInstallDirectory(dir.wstring()) == InstallDirState::Empty);
    std::ofstream(dir / L"other.txt") << "x";
    CHECK(InspectInstallDirectory(dir.wstring()) == InstallDirState::Foreign);
    fs::remove(dir / L"other.txt");
    CHECK(Install(dir, "0.1.0"));
    CHECK(InspectInstallDirectory(dir.wstring()) == InstallDirState::Installed);
    CHECK(InstalledVersion(dir.wstring()) == L"0.1.0");
    fs::remove_all(dir);
}

TEST(InstallWritesFilesSetupCopyAndMarker)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-install");
    CHECK(Install(dir, "0.1.0"));
    CHECK(ReadText(dir / L"approute-gui.exe") == "gui 0.1.0");
    CHECK(ReadText(dir / L"approute-hook64.dll") == "hook 0.1.0");
    CHECK(ReadText(dir / kSetupSubdir / kSetupExeName) == "setup 0.1.0");
    CHECK(ListBackups(dir.wstring()).empty());
    fs::remove_all(dir);
}

TEST(UpdateKeepsTwoBackupsNewestFirst)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-update");
    CHECK(Install(dir, "0.1.0"));
    CHECK(Install(dir, "0.1.1"));
    CHECK(ReadText(dir / L"approute-gui.exe") == "gui 0.1.1");
    auto backups = ListBackups(dir.wstring());
    CHECK(backups.size() == 1);
    CHECK(!backups.empty() && backups[0].version == L"0.1.0");
    CHECK(!backups.empty() && ReadText(fs::path(backups[0].path) / L"approute-gui.exe") == "gui 0.1.0");
    CHECK(!backups.empty() && ReadText(fs::path(backups[0].path) / kSetupSubdir / kSetupExeName) == "setup 0.1.0");

    CHECK(Install(dir, "0.1.2"));
    CHECK(Install(dir, "0.2.0"));
    backups = ListBackups(dir.wstring());
    CHECK(backups.size() == kBackupsKept);
    CHECK(backups.size() == 2 && backups[0].version == L"0.1.2" && backups[1].version == L"0.1.1");
    fs::remove_all(dir);
}

TEST(RollbackSwapsCurrentAndPrevious)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-rollback");
    SetupReport report;
    CHECK(!RollbackFiles(dir.wstring(), &report));   // нет установки
    CHECK(Install(dir, "0.1.0"));
    CHECK(!RollbackFiles(dir.wstring(), &report));   // нет копий
    CHECK(Install(dir, "0.1.1"));
    CHECK(Install(dir, "0.2.0"));

    const auto restored = RollbackFiles(dir.wstring(), &report);
    CHECK(restored == L"0.1.1");
    CHECK(InstalledVersion(dir.wstring()) == L"0.1.1");
    CHECK(ReadText(dir / L"approute-gui.exe") == "gui 0.1.1");
    CHECK(ReadText(dir / kSetupSubdir / kSetupExeName) == "setup 0.1.1");
    const auto backups = ListBackups(dir.wstring());
    CHECK(backups.size() == 2 && backups[0].version == L"0.2.0" && backups[1].version == L"0.1.0");

    CHECK(RollbackFiles(dir.wstring(), &report) == L"0.2.0");   // повторный откат — обратно
    CHECK(ReadText(dir / L"approute-gui.exe") == "gui 0.2.0");
    fs::remove_all(dir);
}

TEST(UpdateMovesFilesInUse)
{
    // hook-DLL, загруженная в запущенную программу, открыта с FILE_SHARE_DELETE — перенос разрешён
    const fs::path dir = FreshDir(L"approute-tests-setup-busy");
    CHECK(Install(dir, "0.1.0"));
    const HANDLE busy = CreateFileW((dir / L"approute-hook64.dll").c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    CHECK(busy != INVALID_HANDLE_VALUE);
    CHECK(Install(dir, "0.1.1"));
    CHECK(ReadText(dir / L"approute-hook64.dll") == "hook 0.1.1");
    CloseHandle(busy);
    fs::remove_all(dir);
}

TEST(UpdateFailureRestoresPreviousFiles)
{
    // Файл открыт без FILE_SHARE_DELETE — перенести нельзя: прежняя версия остаётся на месте
    const fs::path dir = FreshDir(L"approute-tests-setup-locked");
    CHECK(Install(dir, "0.1.0"));
    const HANDLE locked = CreateFileW((dir / L"approute-hook64.dll").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, 0, nullptr);
    CHECK(locked != INVALID_HANDLE_VALUE);
    SetupReport report;
    CHECK(!Install(dir, "0.1.1", &report));
    CHECK(!report.error.empty());
    CloseHandle(locked);
    CHECK(InstalledVersion(dir.wstring()) == L"0.1.0");
    CHECK(ReadText(dir / L"approute-gui.exe") == "gui 0.1.0");
    CHECK(ReadText(dir / kSetupSubdir / kSetupExeName) == "setup 0.1.0");
    CHECK(ListBackups(dir.wstring()).empty());
    fs::remove_all(dir);
}

TEST(InstallRefusesForeignDirectory)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-foreign");
    fs::create_directories(dir);
    std::ofstream(dir / L"document.txt") << "чужой файл";
    SetupReport report;
    CHECK(!Install(dir, "0.1.0", &report));
    CHECK(!report.error.empty());
    CHECK(!RemoveInstallFiles(dir.wstring(), &report));
    CHECK(fs::exists(dir / L"document.txt"));
    CHECK(!fs::exists(dir / L"approute-gui.exe"));
    fs::remove_all(dir);
}

TEST(RemoveInstallFilesDeletesFolderAndBackups)
{
    const fs::path dir = FreshDir(L"approute-tests-setup-remove");
    CHECK(Install(dir, "0.1.0"));
    CHECK(Install(dir, "0.1.1"));
    SetupReport report;
    CHECK(RemoveInstallFiles(dir.wstring(), &report));
    CHECK(!fs::exists(dir));
}

TEST(UninstallValuesPointToSetupCopy)
{
    const auto values = UninstallValues(L"C:\\Users\\u\\AppData\\Local\\Programs\\AppRoute", L"0.2.0", 5000, L"20261111");
    auto get = [&](const wchar_t* name) -> std::wstring {
        for (const auto& v : values) {
            if (v.name == name) {
                if (const auto* s = std::get_if<std::wstring>(&v.value)) {
                    return *s;
                }
            }
        }
        return {};
    };
    CHECK(get(L"DisplayName") == L"AppRoute");
    CHECK(get(L"DisplayVersion") == L"0.2.0");
    CHECK(get(L"UninstallString") ==
          L"\"C:\\Users\\u\\AppData\\Local\\Programs\\AppRoute\\setup\\approute-setup.exe\" --uninstall");
    CHECK(get(L"QuietUninstallString").ends_with(L" --uninstall --silent"));
    CHECK(get(L"ModifyPath") == L"\"C:\\Users\\u\\AppData\\Local\\Programs\\AppRoute\\setup\\approute-setup.exe\"");
}

TEST(ServiceCommandRoundTrip)
{
    const std::wstring command = L"\"C:\\Program Files\\AppRoute\\approute-routes.exe\" service --config "
                                 L"\"C:\\Users\\u v\\AppData\\Roaming\\AppRoute\\config.json\" --client-sid S-1-5-21-1-2-3-1001";
    const auto args = ParseServiceCommand(command);
    CHECK(args.has_value());
    CHECK(args && args->config == L"C:\\Users\\u v\\AppData\\Roaming\\AppRoute\\config.json");
    CHECK(args && args->clientSid == L"S-1-5-21-1-2-3-1001");
    CHECK(args && ServiceReinstallParameters(*args, true) ==
                      L"install-service --config \"C:\\Users\\u v\\AppData\\Roaming\\AppRoute\\config.json\" "
                      L"--client-sid S-1-5-21-1-2-3-1001 --with-driver");
    CHECK(!ParseServiceCommand(L"\"C:\\x\\approute-routes.exe\" service"));
}
