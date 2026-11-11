#include "core/ServiceSetup.h"

#include "core/Shortcuts.h"
#include "core/Util.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <filesystem>
#include <format>
#include <memory>

namespace approute {

namespace {

struct ScHandle {
    SC_HANDLE h = nullptr;
    explicit ScHandle(SC_HANDLE v = nullptr) : h(v) {}
    ~ScHandle()
    {
        if (h) {
            CloseServiceHandle(h);
        }
    }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
};

struct LocalDeleter {
    void operator()(void* p) const { LocalFree(p); }
};

bool Fail(std::wstring* error, const std::wstring& what, DWORD code = GetLastError())
{
    if (error) {
        *error = code ? what + L": " + Win32ErrorMessage(code) : what;
    }
    return false;
}

std::wstring KnownFolder(REFKNOWNFOLDERID id)
{
    PWSTR path = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &path))) {
        out = path;
    }
    CoTaskMemFree(path);
    return out;
}

std::wstring StartMenuShortcut()
{
    return KnownFolder(FOLDERID_CommonPrograms) + L"\\AppRoute.lnk";
}

DWORD QueryState(SC_HANDLE service)
{
    SERVICE_STATUS_PROCESS s{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&s), sizeof(s), &needed)) {
        return 0;
    }
    return s.dwCurrentState;
}

bool WaitState(SC_HANDLE service, DWORD state, DWORD waitMs)
{
    const ULONGLONG deadline = GetTickCount64() + waitMs;
    while (QueryState(service) != state) {
        if (GetTickCount64() >= deadline) {
            return false;
        }
        Sleep(200);
    }
    return true;
}

bool StopService(SC_HANDLE service, DWORD waitMs, std::wstring* error)
{
    const DWORD state = QueryState(service);
    if (state == SERVICE_STOPPED) {
        return true;
    }
    if (state != SERVICE_STOP_PENDING) {
        SERVICE_STATUS status{};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            return Fail(error, L"не удалось остановить службу");
        }
    }
    if (!WaitState(service, SERVICE_STOPPED, waitMs)) {
        return Fail(error, L"служба не остановилась вовремя", 0);
    }
    return true;
}

// Удалить файл; занятый (загруженная hook-DLL, запущенный exe) — переименовать и удалить при
// перезагрузке
void RemoveFile(const std::wstring& path)
{
    if (DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) {
        return;
    }
    const std::wstring old = std::format(L"{}.old-{}", path, GetTickCount64());
    if (MoveFileExW(path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        MoveFileExW(old.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    } else {
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

bool CopyBinary(const std::wstring& from, const std::wstring& to, std::wstring* error)
{
    if (CopyFileW(from.c_str(), to.c_str(), FALSE)) {
        return true;
    }
    RemoveFile(to);   // занят — освободить имя
    if (CopyFileW(from.c_str(), to.c_str(), FALSE)) {
        return true;
    }
    return Fail(error, L"не удалось скопировать " + to);
}

bool OwnedByAdmins(const std::wstring& path)
{
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr,
                              nullptr, &sd) != ERROR_SUCCESS) {
        return false;
    }
    std::unique_ptr<void, LocalDeleter> guard(sd);
    return IsWellKnownSid(owner, WinBuiltinAdministratorsSid) || IsWellKnownSid(owner, WinLocalSystemSid);
}

bool ConfigureService(SC_HANDLE service, const std::wstring& clientSid, std::wstring* error)
{
    std::wstring description =
        L"Держит маршрут в интернет на выбранном в AppRoute интерфейсе и даёт программам с правилами выход "
        L"через их интерфейсы. Политика — из конфига AppRoute; изменения откатываются при остановке.";
    SERVICE_DESCRIPTIONW desc{description.data()};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

    // Только нужные привилегии: остальные SYSTEM у процесса службы отнимаются
    wchar_t privileges[] = L"SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0";
    SERVICE_REQUIRED_PRIVILEGES_INFOW required{privileges};
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &required)) {
        return Fail(error, L"не удалось ограничить привилегии службы");
    }
    SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid);

    SC_ACTION actions[] = {{SC_ACTION_RESTART, 10000}, {SC_ACTION_RESTART, 60000}, {SC_ACTION_NONE, 0}};
    SERVICE_FAILURE_ACTIONSW failure{};
    failure.dwResetPeriod = 24 * 60 * 60;
    failure.cActions = static_cast<DWORD>(std::size(actions));
    failure.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ServiceSecurityDescriptor(clientSid).c_str(),
                                                              SDDL_REVISION_1, &sd, nullptr)) {
        return Fail(error, L"не удалось подготовить права службы");
    }
    std::unique_ptr<void, LocalDeleter> guard(sd);
    if (!SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd)) {
        return Fail(error, L"не удалось задать права службы");
    }
    return true;
}

// Файлы и ярлык установки
void RemoveInstalledFiles(const std::wstring& dir)
{
    for (const auto& name : AppRouteBinaries(dir)) {
        RemoveFile(dir + L"\\" + name);
    }
    if (!RemoveDirectoryW(dir.c_str())) {
        MoveFileExW(dir.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);   // удалится после файлов
    }
    DeleteFileW(StartMenuShortcut().c_str());
}

} // namespace

std::wstring InstallDirectory()
{
    return KnownFolder(FOLDERID_ProgramFiles) + L"\\AppRoute";
}

std::vector<std::wstring> AppRouteBinaries(const std::wstring& dir)
{
    namespace fs = std::filesystem;
    std::vector<std::wstring> out;
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_regular_file(ec)) {
            continue;
        }
        const std::wstring name = it->path().filename().wstring();
        const std::wstring ext = it->path().extension().wstring();
        if (!name.starts_with(L"approute-") && !name.starts_with(L"APPROUTE-")) {
            continue;
        }
        const bool exe = EqualsIgnoreCase(ext, L".exe");
        const bool hook = EqualsIgnoreCase(ext, L".dll") && name.size() > 13 &&
                          EqualsIgnoreCase(std::wstring_view(name).substr(0, 13), L"approute-hook");
        if ((exe || hook) && !EqualsIgnoreCase(name, L"approute-tests.exe")) {
            out.push_back(name);
        }
    }
    return out;
}

std::wstring ServiceCommandLine(const std::wstring& exe, const std::wstring& configPath, const std::wstring& clientSid)
{
    return QuoteArgument(exe) + L" service --config " + QuoteArgument(configPath) + L" --client-sid " +
           QuoteArgument(clientSid);
}

std::wstring ServiceSecurityDescriptor(const std::wstring& clientSid)
{
    // Стандартные права служб + запуск (RP), остановка (WP) и опрос — пользователю, давшему согласие
    return L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)"
           L"(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPLOCRRC;;;" +
           clientSid + L")";
}

ServiceState QueryServiceState()
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ScHandle service(scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_STATUS) : nullptr);
    if (!service.h) {
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? ServiceState::NotInstalled : ServiceState::Unknown;
    }
    switch (QueryState(service.h)) {
    case SERVICE_STOPPED: return ServiceState::Stopped;
    case SERVICE_START_PENDING: return ServiceState::Starting;
    case SERVICE_RUNNING: return ServiceState::Running;
    case SERVICE_STOP_PENDING: return ServiceState::Stopping;
    default: return ServiceState::Unknown;
    }
}

bool StartAppRouteService(std::wstring* error)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ScHandle service(scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS) : nullptr);
    if (!service.h) {
        return Fail(error, L"нет доступа к службе AppRoute");
    }
    if (!StartServiceW(service.h, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        return Fail(error, L"не удалось запустить службу AppRoute");
    }
    return true;
}

bool StopAppRouteService(std::wstring* error, DWORD waitMs)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ScHandle service(scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS) : nullptr);
    if (!service.h) {
        return Fail(error, L"нет доступа к службе AppRoute");
    }
    return StopService(service.h, waitMs, error);
}

bool InstallAppRouteService(const std::wstring& sourceDir, const std::wstring& configPath,
                            const std::wstring& clientSid, std::wstring* error, bool withDriver,
                            std::wstring* driverNote)
{
    if (clientSid.empty() || configPath.empty()) {
        return Fail(error, L"не указан пользователь или файл правил", 0);
    }
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.h) {
        return Fail(error, L"нет доступа к диспетчеру служб (нужны права администратора)");
    }
    ScHandle existing(OpenServiceW(scm.h, kServiceName, SERVICE_ALL_ACCESS));
    if (existing.h && !StopService(existing.h, 20000, error)) {
        return false;
    }

    // Файлы — в Program Files: туда не может писать обычная программа
    const std::wstring dir = InstallDirectory();
    if (dir.size() < 4) {
        return Fail(error, L"не найдена папка Program Files", 0);
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    if (!OwnedByAdmins(dir)) {
        return Fail(error, dir + L" принадлежит не администраторам — установка прервана", 0);
    }
    const auto files = AppRouteBinaries(sourceDir);
    if (std::find(files.begin(), files.end(), L"approute-routes.exe") == files.end()) {
        return Fail(error, L"в " + sourceDir + L" нет approute-routes.exe", 0);
    }
    if (!EqualsIgnoreCase(sourceDir, dir)) {
        for (const auto& name : files) {
            if (!CopyBinary(sourceDir + L"\\" + name, dir + L"\\" + name, error)) {
                return false;
            }
        }
    }

    const std::wstring command = ServiceCommandLine(dir + L"\\approute-routes.exe", configPath, clientSid);
    ScHandle created;
    SC_HANDLE service = existing.h;
    if (service) {
        if (!ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, kServiceDisplayName)) {
            return Fail(error, L"не удалось обновить службу");
        }
    } else {
        created.h = CreateServiceW(scm.h, kServiceName, kServiceDisplayName, SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr);   // LocalSystem
        if (!created.h) {
            return Fail(error, L"не удалось создать службу");
        }
        service = created.h;
    }
    if (!ConfigureService(service, clientSid, error)) {
        return false;
    }

    // Драйвер — до запуска службы: она применяет правила через него сразу при старте
    bool driverInstalled = false;
    if (withDriver) {
        std::wstring why;
        const std::wstring sys = sourceDir + L"\\approute-wfp.sys";
        if (GetFileAttributesW(sys.c_str()) == INVALID_FILE_ATTRIBUTES) {
            why = L"нет файла " + sys;
        } else if (InstallWfpDriver(sys, &why)) {
            driverInstalled = true;
        } else {
            std::wstring ignored;
            UninstallWfpDriver(&ignored);   // не оставляем незагружаемую службу драйвера
        }
        if (driverNote && !driverInstalled) {
            *driverNote = L"драйвер approute-wfp не установлен (" + why +
                          L") — правила действуют только для программ, запущенных через AppRoute";
        }
    }

    // Ярлык установленного окна: только оно может управлять менеджером по каналу
    ShortcutSpec spec;
    spec.target = dir + L"\\approute-gui.exe";
    spec.workingDirectory = dir;
    spec.iconPath = spec.target;
    spec.description = L"AppRoute — маршрутизация по приложениям";
    std::wstring ignored;
    SaveShortcut(StartMenuShortcut(), spec, &ignored);

    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        // Не оставляем в системе службу, которая не запускается: откат установки
        const DWORD code = GetLastError();
        DeleteService(service);
        if (driverInstalled) {
            UninstallWfpDriver(&ignored);
        }
        RemoveInstalledFiles(dir);
        std::wstring why = L"служба не запустилась (" + Win32ErrorMessage(code) + L"), установка отменена";
        if (code == ERROR_ACCESS_DENIED) {
            why += L". Запуск, вероятно, запретил антивирус или политика компьютера: AppRoute их не обходит. "
                   L"Можно разрешить службу в настройках антивируса (если это ваш компьютер) или запускать "
                   L"менеджер маршрутов из окна без службы";
        }
        return Fail(error, why, 0);
    }
    return true;
}

bool UninstallAppRouteService(std::wstring* error)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.h) {
        return Fail(error, L"нет доступа к диспетчеру служб (нужны права администратора)");
    }
    ScHandle service(OpenServiceW(scm.h, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (service.h) {
        if (!StopService(service.h, 20000, error)) {
            return false;
        }
        if (!DeleteService(service.h) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Fail(error, L"не удалось удалить службу");
        }
    } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        return Fail(error, L"нет доступа к службе AppRoute");
    }
    // Служба остановлена — её фильтры WFP сняты, драйвер можно выгрузить
    if (!UninstallWfpDriver(error)) {
        return false;
    }
    RemoveInstalledFiles(InstallDirectory());
    return true;
}

bool InstallWfpDriver(const std::wstring& sysPath, std::wstring* error)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.h) {
        return Fail(error, L"нет доступа к диспетчеру служб (нужны права администратора)");
    }
    ScHandle existing(OpenServiceW(scm.h, kDriverServiceName, SERVICE_ALL_ACCESS));
    if (existing.h && !StopService(existing.h, 10000, error)) {
        return false;
    }
    const std::wstring dir = InstallDirectory();
    if (dir.size() < 4) {
        return Fail(error, L"не найдена папка Program Files", 0);
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    if (!OwnedByAdmins(dir)) {
        return Fail(error, dir + L" принадлежит не администраторам — установка прервана", 0);
    }
    const std::wstring target = dir + L"\\approute-wfp.sys";
    if (!EqualsIgnoreCase(sysPath, target) && !CopyBinary(sysPath, target, error)) {
        return false;
    }
    SC_HANDLE service = existing.h;
    ScHandle created;
    if (service) {
        if (!ChangeServiceConfigW(service, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                  target.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                  L"AppRoute — драйвер WFP")) {
            return Fail(error, L"не удалось обновить службу драйвера");
        }
    } else {
        created.h = CreateServiceW(scm.h, kDriverServiceName, L"AppRoute — драйвер WFP", SERVICE_ALL_ACCESS,
                                   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, target.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!created.h) {
            return Fail(error, L"не удалось создать службу драйвера");
        }
        service = created.h;
    }
    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        const DWORD code = GetLastError();
        std::wstring why = L"драйвер не загрузился: " + Win32ErrorMessage(code);
        if (code == ERROR_INVALID_IMAGE_HASH) {
            why += L" — подпись не принята: тестовая подпись работает только в тестовом режиме (bcdedit /set testsigning on)";
        }
        return Fail(error, why, 0);
    }
    return true;
}

bool UninstallWfpDriver(std::wstring* error)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.h) {
        return Fail(error, L"нет доступа к диспетчеру служб (нужны права администратора)");
    }
    ScHandle service(OpenServiceW(scm.h, kDriverServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (service.h) {
        if (!StopService(service.h, 10000, error)) {
            return false;
        }
        if (!DeleteService(service.h) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Fail(error, L"не удалось удалить службу драйвера");
        }
    } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        return Fail(error, L"нет доступа к службе драйвера");
    }
    RemoveFile(InstallDirectory() + L"\\approute-wfp.sys");
    return true;
}

WfpDriverState QueryWfpDriver()
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) {
        return WfpDriverState::NotInstalled;
    }
    ScHandle service(OpenServiceW(scm.h, kDriverServiceName, SERVICE_QUERY_STATUS));
    if (!service.h) {
        return WfpDriverState::NotInstalled;
    }
    SERVICE_STATUS status{};
    if (QueryServiceStatus(service.h, &status) && status.dwCurrentState == SERVICE_RUNNING) {
        return WfpDriverState::Running;
    }
    return WfpDriverState::Stopped;
}

bool StartWfpDriver(std::wstring* error)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) {
        return Fail(error, L"нет доступа к диспетчеру служб");
    }
    ScHandle service(OpenServiceW(scm.h, kDriverServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
    if (!service.h) {
        return Fail(error, L"нет доступа к службе драйвера");
    }
    if (!StartServiceW(service.h, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        return Fail(error, L"драйвер не загрузился");
    }
    return true;
}

HANDLE OpenProtectedLog(const std::wstring& dir, const std::wstring& file)
{
    // SYSTEM и администраторы — полный доступ, пользователи — чтение
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1, &sd, nullptr)) {
        return nullptr;
    }
    std::unique_ptr<void, LocalDeleter> guard(sd);
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};

    const DWORD attrs = GetFileAttributesW(dir.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) || !(attrs & FILE_ATTRIBUTE_DIRECTORY) || !OwnedByAdmins(dir))) {
        // Папку создал не администратор (или это ссылка) — не доверяем ей
        const std::wstring aside = std::format(L"{}.untrusted-{}", dir, GetTickCount64());
        if (!MoveFileExW(dir.c_str(), aside.c_str(), 0)) {
            return nullptr;
        }
    }
    if (!CreateDirectoryW(dir.c_str(), &sa) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return nullptr;
    }
    if (!OwnedByAdmins(dir)) {
        return nullptr;
    }

    const std::wstring path = dir + L"\\" + file;
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info) &&
        !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && (info.nFileSizeHigh || info.nFileSizeLow > 1024 * 1024)) {
        MoveFileExW(path.c_str(), (path + L".1").c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    const HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    BY_HANDLE_FILE_INFORMATION fi{};
    if (!GetFileInformationByHandle(h, &fi) || (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        fi.nNumberOfLinks > 1) {
        CloseHandle(h);   // ссылка или жёсткая ссылка на чужой файл
        return nullptr;
    }
    return h;
}

} // namespace approute
