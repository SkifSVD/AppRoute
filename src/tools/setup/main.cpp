// approute-setup — установщик AppRoute (#64).
//
// Один exe: файлы AppRoute вложены в него ресурсами (build.ps1 -Publish -Installer). Установка
// для текущего пользователя в %LOCALAPPDATA%\Programs\AppRoute, без прав администратора;
// обновление — поверх, с резервной копией прежней версии; откат; удаление через «Приложения».
// Логика — в core/Setup; здесь — окна, аргументы и запуск approute-routes для службы.
//
//   approute-setup                         окно: установка или меню (обновить, откатить, удалить)
//   approute-setup --install [--dir D] [--no-shortcuts] [--silent]
//   approute-setup --rollback [--dir D] [--silent]
//   approute-setup --uninstall [--dir D] [--remove-settings] [--silent]
//
// Коды выхода: 0 — готово, 1 — ошибка, 2 — отменено или нечего делать. Журнал —
// %TEMP%\approute-setup.log.

#include "core/Launcher.h"
#include "core/ServiceSetup.h"
#include "core/Setup.h"
#include "core/Shortcuts.h"
#include "core/Util.h"
#include "core/Version.h"

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <cstddef>
#include <filesystem>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace approute;

namespace {

constexpr int kExitOk = 0;
constexpr int kExitError = 1;
constexpr int kExitCancelled = 2;
constexpr DWORD kGuiCloseWaitMs = 30000;
constexpr int kPayloadIndexId = 999;
constexpr wchar_t kTitle[] = L"Установка AppRoute";

enum class Action { Menu, Install, Rollback, Uninstall, Cleanup };

struct Options {
    Action action = Action::Menu;
    std::wstring dir;
    bool silent = false;
    bool noShortcuts = false;
    bool removeSettings = false;
    bool help = false;
    DWORD waitPid = 0;
    std::wstring bad;   // нераспознанный аргумент
};

// --- журнал ---------------------------------------------------------------------------------

std::wstring TempPath(std::wstring_view name)
{
    wchar_t buf[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH, buf);
    return std::wstring(buf) + std::wstring(name);
}

void Log(std::wstring_view line)
{
    const HANDLE h = CreateFileW(TempPath(L"approute-setup.log").c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    SYSTEMTIME t{};
    GetLocalTime(&t);
    const std::string text = ToUtf8(std::format(L"{:04}-{:02}-{:02} {:02}:{:02}:{:02} [{}] {}\r\n", t.wYear, t.wMonth,
                                                t.wDay, t.wHour, t.wMinute, t.wSecond, GetCurrentProcessId(), line));
    DWORD written = 0;
    WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    CloseHandle(h);
}

// --- окна -----------------------------------------------------------------------------------

struct Button {
    int id;
    std::wstring text;
    bool shield = false;
};

struct Answer {
    int id = IDCANCEL;
    bool verified = false;
};

HRESULT CALLBACK ShieldCallback(HWND dialog, UINT msg, WPARAM, LPARAM, LONG_PTR data)
{
    if (msg == TDN_CREATED) {
        for (const Button& b : *reinterpret_cast<const std::vector<Button>*>(data)) {
            if (b.shield) {
                SendMessageW(dialog, TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE, b.id, TRUE);
            }
        }
    }
    return S_OK;
}

Answer Ask(PCWSTR icon, const std::wstring& instruction, const std::wstring& content, const std::vector<Button>& buttons,
           bool commandLinks, const std::wstring& verification = {}, bool verifiedByDefault = false,
           bool withCancel = true)
{
    std::vector<TASKDIALOG_BUTTON> raw;
    for (const Button& b : buttons) {
        raw.push_back({b.id, b.text.c_str()});
    }
    TASKDIALOGCONFIG tdc{};
    tdc.cbSize = sizeof(tdc);
    tdc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | (commandLinks ? TDF_USE_COMMAND_LINKS : 0) |
                  (verifiedByDefault ? TDF_VERIFICATION_FLAG_CHECKED : 0);
    tdc.pszWindowTitle = kTitle;
    tdc.pszMainIcon = icon;
    tdc.pszMainInstruction = instruction.c_str();
    tdc.pszContent = content.empty() ? nullptr : content.c_str();
    tdc.cButtons = static_cast<UINT>(raw.size());
    tdc.pButtons = raw.data();
    tdc.dwCommonButtons = withCancel ? TDCBF_CANCEL_BUTTON : 0;
    tdc.pszVerificationText = verification.empty() ? nullptr : verification.c_str();
    tdc.pfCallback = ShieldCallback;
    tdc.lpCallbackData = reinterpret_cast<LONG_PTR>(&buttons);
    Answer answer;
    BOOL verified = FALSE;
    if (FAILED(TaskDialogIndirect(&tdc, &answer.id, nullptr, &verified))) {
        answer.id = IDCANCEL;
    }
    answer.verified = verified == TRUE;
    return answer;
}

void Show(PCWSTR icon, const std::wstring& instruction, const std::wstring& content)
{
    TaskDialog(nullptr, nullptr, kTitle, instruction.c_str(), content.empty() ? nullptr : content.c_str(),
               TDCBF_OK_BUTTON, icon, nullptr);
}

std::wstring Lines(const std::vector<std::wstring>& notes)
{
    std::wstring out;
    for (const auto& n : notes) {
        out += (out.empty() ? L"" : L"\n\n") + (L"⚠ " + n);
    }
    return out;
}

// Ошибка: в журнал и (без --silent) в окно
int Failure(const Options& o, const std::wstring& instruction, const std::wstring& why)
{
    Log(L"Ошибка: " + instruction + L": " + why);
    if (!o.silent) {
        Show(TD_ERROR_ICON, instruction, why);
    }
    return kExitError;
}

std::optional<std::wstring> PickFolder(const std::wstring& initial)
{
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) {
        return std::nullopt;
    }
    std::optional<std::wstring> out;
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dialog->SetTitle(L"Папка установки AppRoute");
    IShellItem* folder = nullptr;
    const std::wstring parent = std::filesystem::path(initial).parent_path().wstring();
    if (SUCCEEDED(SHCreateItemFromParsingName(parent.c_str(), nullptr, IID_PPV_ARGS(&folder)))) {
        dialog->SetFolder(folder);
        folder->Release();
    }
    IShellItem* item = nullptr;
    if (SUCCEEDED(dialog->Show(nullptr)) && SUCCEEDED(dialog->GetResult(&item))) {
        PWSTR path = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
            out = path;
            CoTaskMemFree(path);
        }
        item->Release();
    }
    dialog->Release();
    return out;
}

// --- вложенные файлы ------------------------------------------------------------------------

std::span<const std::byte> ResourceBytes(int id)
{
    const HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    const HGLOBAL data = res ? LoadResource(nullptr, res) : nullptr;
    const void* bytes = data ? LockResource(data) : nullptr;
    if (!bytes) {
        return {};
    }
    return {static_cast<const std::byte*>(bytes), SizeofResource(nullptr, res)};
}

// Оглавление (ресурс 999): строки «<id> <имя файла>» в UTF-8
std::vector<PayloadFile> LoadPayload()
{
    std::vector<PayloadFile> out;
    const auto index = ResourceBytes(kPayloadIndexId);
    const std::string text(reinterpret_cast<const char*>(index.data()), index.size());
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) {
            end = text.size();
        }
        std::string line = text.substr(start, end - start);
        start = end + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        const size_t space = line.find(' ');
        if (space == std::string::npos) {
            continue;
        }
        const int id = std::atoi(line.substr(0, space).c_str());
        const auto name = FromUtf8(line.substr(space + 1));
        const auto bytes = ResourceBytes(id);
        if (name && !bytes.empty()) {
            out.push_back({*name, bytes});
        }
    }
    return out;
}

std::wstring SelfPath()
{
    std::wstring buf(MAX_PATH * 2, L'\0');
    buf.resize(GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size())));
    return buf;
}

// Свой exe целиком — копия в setup\ папки установки (читается до переноса файлов в резервную копию)
std::vector<std::byte> ReadSelf()
{
    std::vector<std::byte> out;
    const HANDLE h = CreateFileW(SelfPath().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return out;
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart < (1LL << 30)) {
        out.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr) || read != out.size()) {
            out.clear();
        }
    }
    CloseHandle(h);
    return out;
}

bool PathInside(const std::wstring& path, const std::wstring& dir)
{
    const std::wstring d = dir.ends_with(L'\\') ? dir : dir + L'\\';
    return path.size() > d.size() && EqualsIgnoreCase(std::wstring_view(path).substr(0, d.size()), d);
}

// --- служба AppRoute ------------------------------------------------------------------------

// Последняя строка %ProgramData%\AppRoute\install.log — итог install-service / uninstall-service
std::wstring LastInstallMessage()
{
    wchar_t data[MAX_PATH * 2] = {};
    if (!GetEnvironmentVariableW(L"ProgramData", data, static_cast<DWORD>(std::size(data)))) {
        return {};
    }
    const HANDLE h = CreateFileW((std::wstring(data) + L"\\AppRoute\\install.log").c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return {};
    }
    std::string text(64 * 1024, '\0');
    DWORD read = 0;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(h, &size) && size.QuadPart > static_cast<LONGLONG>(text.size())) {
        LARGE_INTEGER pos{};
        pos.QuadPart = size.QuadPart - static_cast<LONGLONG>(text.size());
        SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    }
    ReadFile(h, text.data(), static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(h);
    text.resize(read);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    const size_t line = text.rfind('\n');
    std::wstring last = FromUtf8(line == std::string::npos ? text : text.substr(line + 1)).value_or(L"");
    if (const size_t bracket = last.find(L"] "); last.starts_with(L"[") && bracket != std::wstring::npos) {
        last = last.substr(bracket + 2);   // без отметки времени
    }
    return last;
}

enum class ServiceStep { Done, Skipped, Cancelled, Failed };

// approute-routes из папки установки с правами администратора (запрос UAC)
ServiceStep RunRoutesElevated(const Options& o, const std::wstring& dir, const std::wstring& params,
                              std::wstring* message)
{
    if (o.silent && !IsProcessElevated()) {
        *message = L"нужны права администратора, а в тихом режиме запрос UAC не показывается";
        return ServiceStep::Skipped;
    }
    const std::wstring routes = dir + L"\\approute-routes.exe";
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = routes.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    Log(L"approute-routes " + params + L" (с правами администратора)");
    if (!ShellExecuteExW(&sei)) {
        const DWORD error = GetLastError();
        *message = error == ERROR_CANCELLED ? L"запрос прав администратора отклонён" : Win32ErrorMessage(error);
        return error == ERROR_CANCELLED ? ServiceStep::Cancelled : ServiceStep::Failed;
    }
    DWORD code = 1;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 120000);
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
    }
    if (code != 0) {
        *message = LastInstallMessage();
        if (message->empty()) {
            *message = std::format(L"approute-routes завершился с кодом {}", code);
        }
        return ServiceStep::Failed;
    }
    return ServiceStep::Done;
}

// Служба AppRoute установлена — переустановить её из новых файлов с теми же настройками
void RefreshService(const Options& o, const std::wstring& dir, SetupReport* report)
{
    if (QueryServiceState() == ServiceState::NotInstalled) {
        return;
    }
    const std::wstring manual = L"Служба AppRoute осталась прежней версии. Обновить её: окно AppRoute → «Установить "
                                L"службу» (или запустите установщик ещё раз).";
    const auto command = InstalledServiceCommand();
    const auto args = command ? ParseServiceCommand(*command) : std::nullopt;
    if (!args) {
        report->notes.push_back(L"Не удалось прочитать параметры службы AppRoute. " + manual);
        return;
    }
    if (!o.silent) {
        const Answer a = Ask(TD_INFORMATION_ICON, L"Обновить службу AppRoute?",
                             L"Служба AppRoute (менеджер маршрутов) установлена в %ProgramFiles%\\AppRoute и работает "
                             L"в прежней версии. Её обновление требует прав администратора; правила и настройки "
                             L"службы сохранятся.",
                             {{100, L"Обновить службу", true}, {101, L"Позже"}}, false, L"", false, false);
        if (a.id != 100) {
            report->notes.push_back(manual);
            return;
        }
    }
    std::wstring message;
    const bool withDriver = QueryWfpDriver() != WfpDriverState::NotInstalled;
    switch (RunRoutesElevated(o, dir, ServiceReinstallParameters(*args, withDriver), &message)) {
    case ServiceStep::Done:
        Log(L"Служба AppRoute обновлена");
        break;
    case ServiceStep::Skipped:
    case ServiceStep::Cancelled:
        report->notes.push_back(manual + L" (" + message + L")");
        break;
    case ServiceStep::Failed:
        report->notes.push_back(L"Служба AppRoute не обновилась: " + message);
        break;
    }
}

// Окно правил — с прежними аргументами (например, --config), если оно было открыто
void LaunchGui(const std::wstring& dir, const std::wstring& arguments)
{
    const std::wstring gui = dir + L"\\approute-gui.exe";
    ShellExecuteW(nullptr, L"open", gui.c_str(), arguments.empty() ? nullptr : arguments.c_str(), dir.c_str(),
                  SW_SHOWNORMAL);
}

// Итог: журнал, окно с замечаниями и флажком «Запустить AppRoute»
void Finish(const Options& o, const std::wstring& dir, const std::wstring& instruction, const SetupReport& report,
            bool offerLaunch, bool launchByDefault, const std::wstring& guiArguments = {})
{
    Log(instruction);
    for (const auto& n : report.notes) {
        Log(L"  " + n);
    }
    if (o.silent) {
        if (offerLaunch && launchByDefault) {
            LaunchGui(dir, guiArguments);
        }
        return;
    }
    const std::wstring content = Lines(report.notes);
    const Answer a = Ask(report.notes.empty() ? TD_INFORMATION_ICON : TD_WARNING_ICON, instruction,
                         content.empty() ? L"Папка: " + dir : content, {{IDOK, L"Готово"}}, false,
                         offerLaunch ? L"Запустить AppRoute" : L"", launchByDefault, false);
    if (offerLaunch && a.verified) {
        LaunchGui(dir, guiArguments);
    }
}

// --- действия -------------------------------------------------------------------------------

int Install(const Options& o, const std::wstring& dir)
{
    const auto payload = LoadPayload();
    if (payload.empty()) {
        return Failure(o, L"AppRoute не установлен", L"в установщике нет файлов программы — он собран без -Installer");
    }
    const std::vector<std::byte> self = ReadSelf();
    const auto previous = InstalledVersion(dir);
    const bool hadShortcut = GetFileAttributesW(StartMenuShortcutPath().c_str()) != INVALID_FILE_ATTRIBUTES;
    Log(std::format(L"Установка {} в {} (было: {})", AppRouteVersion(), dir, previous.value_or(L"нет")));

    SetupReport report;
    bool guiWasRunning = false;
    std::wstring guiArguments;
    if (!CloseRunningGui(dir, kGuiCloseWaitMs, &guiWasRunning, &guiArguments)) {
        report.notes.push_back(L"Окно AppRoute прежней версии не закрылось. Закройте его (значок в трее → «Выход») "
                               L"и откройте снова.");
    }
    const HCURSOR cursor = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    const bool ok = InstallFiles(dir, payload, AppRouteVersion(), self, &report);
    SetCursor(cursor);
    if (!ok) {
        return Failure(o, L"AppRoute не установлен", report.error);
    }
    std::wstring error;
    if (!WriteUninstallEntry(dir, AppRouteVersion(), &error)) {
        report.notes.push_back(error);
    }
    if (!o.noShortcuts && (!previous || hadShortcut) && !CreateStartMenuShortcut(dir, &error)) {
        report.notes.push_back(L"Ярлык в меню «Пуск» не создан: " + error);
    }
    RefreshService(o, dir, &report);

    const std::wstring done =
        !previous ? std::format(L"AppRoute {} установлен", AppRouteVersion())
        : CompareVersions(*previous, AppRouteVersion()) == 0
            ? std::format(L"AppRoute {} переустановлен", AppRouteVersion())
            : std::format(L"AppRoute обновлён: {} → {}", *previous, AppRouteVersion());
    Finish(o, dir, done, report, true, !o.silent || guiWasRunning, guiArguments);
    return kExitOk;
}

int Rollback(const Options& o, const std::wstring& dir)
{
    const auto backups = ListBackups(dir);
    if (backups.empty()) {
        Log(L"Откат: нет сохранённой предыдущей версии в " + dir);
        if (!o.silent) {
            Show(TD_INFORMATION_ICON, L"Откатывать некуда", L"Предыдущая версия AppRoute не сохранена: копия делается "
                                                            L"при обновлении.");
        }
        return kExitCancelled;
    }
    const auto current = InstalledVersion(dir);
    Log(std::format(L"Откат {} → {} в {}", current.value_or(L"?"), backups.front().version, dir));
    SetupReport report;
    bool guiWasRunning = false;
    std::wstring guiArguments;
    if (!CloseRunningGui(dir, kGuiCloseWaitMs, &guiWasRunning, &guiArguments)) {
        report.notes.push_back(L"Окно AppRoute не закрылось. Закройте его (значок в трее → «Выход») и откройте снова.");
    }
    const auto restored = RollbackFiles(dir, &report);
    if (!restored) {
        return Failure(o, L"Откат не выполнен", report.error);
    }
    std::wstring error;
    if (!WriteUninstallEntry(dir, *restored, &error)) {
        report.notes.push_back(error);
    }
    RefreshService(o, dir, &report);
    Finish(o, dir,
           std::format(L"AppRoute откачен: {} → {}. Повторный откат вернёт {}", current.value_or(L"?"), *restored,
                       current.value_or(L"прежнюю версию")),
           report, true, !o.silent || guiWasRunning, guiArguments);
    return kExitOk;
}

// Удаление из папки, где лежит сам установщик: остаток удаляет его копия во временной папке
// после выхода этого процесса
void ScheduleCleanup(const std::wstring& dir)
{
    const std::wstring copy = TempPath(L"approute-setup-cleanup.exe");
    if (!CopyFileW(SelfPath().c_str(), copy.c_str(), FALSE)) {
        Log(L"Не удалось подготовить удаление остатка: " + Win32ErrorMessage(GetLastError()));
        return;
    }
    std::wstring cmd = QuoteArgument(copy) + L" --cleanup --dir " + QuoteArgument(dir) +
                       std::format(L" --wait {}", GetCurrentProcessId());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(copy.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

int Cleanup(const Options& o)
{
    if (o.waitPid) {
        if (const HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, o.waitPid)) {
            WaitForSingleObject(parent, 60000);
            CloseHandle(parent);
        }
    }
    for (int i = 0; i < 20; ++i) {
        if (InspectInstallDirectory(o.dir) != InstallDirState::Installed || RemoveInstallFiles(o.dir, nullptr)) {
            Log(L"Папка установки удалена: " + o.dir);
            return kExitOk;
        }
        Sleep(500);
    }
    Log(L"Папка установки удалена не полностью: " + o.dir);
    return kExitError;
}

int Uninstall(const Options& o, const std::wstring& dir, bool removeSettings)
{
    const InstallDirState state = InspectInstallDirectory(dir);
    if (state != InstallDirState::Installed && state != InstallDirState::Missing) {
        return Failure(o, L"AppRoute не удалён", L"в папке " + dir + L" нет установки AppRoute");
    }
    Log(std::format(L"Удаление AppRoute {} из {}{}", InstalledVersion(dir).value_or(L"?"), dir,
                    removeSettings ? L" с настройками" : L""));
    SetupReport report;

    // Служба и драйвер — первыми: их удаляет approute-routes из папки установки
    if (QueryServiceState() != ServiceState::NotInstalled) {
        std::wstring message;
        const std::wstring routesDir = state == InstallDirState::Installed ? dir : InstallDirectory();
        switch (RunRoutesElevated(o, routesDir, L"uninstall-service", &message)) {
        case ServiceStep::Done:
            Log(L"Служба AppRoute удалена");
            break;
        case ServiceStep::Cancelled:
            Log(L"Удаление отменено: " + message);
            if (!o.silent) {
                Show(TD_INFORMATION_ICON, L"Удаление отменено",
                     L"Служба AppRoute установлена от имени администратора — без её удаления AppRoute не удаляется.");
            }
            return kExitCancelled;
        case ServiceStep::Skipped:
        case ServiceStep::Failed:
            return Failure(o, L"AppRoute не удалён", L"служба AppRoute не удалена: " + message);
        }
    }

    if (!CloseRunningGui(dir, kGuiCloseWaitMs, nullptr)) {
        report.notes.push_back(L"Окно AppRoute не закрылось — его файлы удалятся после выхода из него.");
    }
    RestorePackageDebugging();
    RemoveAutostartFor(dir);
    RemoveUserShortcuts(dir);
    RemoveUninstallEntry();

    const std::wstring self = SelfPath();
    const bool selfInside = PathInside(self, dir);
    if (state == InstallDirState::Installed && !RemoveInstallFiles(dir, &report) && selfInside) {
        // Сам установщик ещё работает — его и папку удалит копия после выхода
        std::erase_if(report.notes, [&](const std::wstring& n) {
            return n.ends_with(self) || n.ends_with(std::filesystem::path(self).parent_path().wstring());
        });
    }
    if (selfInside) {
        ScheduleCleanup(dir);
    }
    if (removeSettings) {
        RemoveUserSettings(&report);
    }
    Finish(o, dir,
           removeSettings ? L"AppRoute удалён вместе с правилами и настройками"
                          : L"AppRoute удалён. Правила и настройки остались в %APPDATA%\\AppRoute",
           report, false, false);
    return kExitOk;
}

int ConfirmUninstall(const Options& o, const std::wstring& dir)
{
    if (o.silent) {
        return Uninstall(o, dir, o.removeSettings);
    }
    const Answer a =
        Ask(TD_WARNING_ICON, std::format(L"Удалить AppRoute {}?", InstalledVersion(dir).value_or(L"")),
            L"Будут удалены программа, её резервные копии, ярлыки AppRoute и запись автозапуска" +
                std::wstring(QueryServiceState() != ServiceState::NotInstalled
                                 ? L", а также служба и драйвер AppRoute (нужны права администратора)."
                                 : L".") +
                L"\n\nПапка: " + dir,
            {{100, L"Удалить", QueryServiceState() != ServiceState::NotInstalled}}, false,
            L"Удалить и правила с настройками (%APPDATA%\\AppRoute, журналы, пароли прокси)", o.removeSettings);
    if (a.id != 100) {
        return kExitCancelled;
    }
    return Uninstall(o, dir, a.verified);
}

// Окно без ключей: новая установка или меню действий
int Menu(Options o, std::wstring dir)
{
    const std::wstring version = AppRouteVersion();
    for (;;) {
        const InstallDirState state = InspectInstallDirectory(dir);
        if (state == InstallDirState::Installed) {
            break;
        }
        const Answer a = Ask(
            nullptr, std::format(L"Установить AppRoute {}?", version),
            L"Папка: " + dir +
                L"\n\nУстановка только для вас, права администратора не нужны. Правила и настройки хранятся отдельно "
                L"(%APPDATA%\\AppRoute) и при обновлении не меняются.",
            {{100, L"Установить"}, {101, L"Другая папка…"}}, false, L"Ярлык в меню «Пуск»", true);
        if (a.id == 101) {
            if (const auto picked = PickFolder(dir)) {
                const InstallDirState pickedState = InspectInstallDirectory(*picked);
                dir = pickedState == InstallDirState::Foreign ? *picked + L"\\AppRoute" : *picked;
            }
            continue;
        }
        if (a.id != 100) {
            return kExitCancelled;
        }
        if (state == InstallDirState::Foreign) {
            Show(TD_WARNING_ICON, L"Папка занята", L"В папке " + dir + L" уже есть другие файлы — выберите другую.");
            continue;
        }
        o.noShortcuts = !a.verified;
        return Install(o, dir);
    }

    const std::wstring installed = InstalledVersion(dir).value_or(L"?");
    const auto backups = ListBackups(dir);
    const int cmp = CompareVersions(installed, version);
    std::vector<Button> buttons;
    buttons.push_back({100, cmp < 0    ? std::format(L"Обновить до {}\nТекущая версия {} сохранится — к ней можно "
                                                     L"будет откатиться",
                                                     version, installed)
                            : cmp == 0 ? std::format(L"Переустановить {}", version)
                                       : std::format(L"Установить {}\nЭто более старая версия, чем установленная {}",
                                                     version, installed)});
    if (!backups.empty()) {
        buttons.push_back({101, std::format(L"Откатить к {}\nВернуть сохранённую версию; текущая {} сохранится",
                                            backups.front().version, installed)});
    }
    buttons.push_back({102, L"Удалить AppRoute"});
    const Answer a = Ask(nullptr, std::format(L"AppRoute {} установлен", installed), L"Папка: " + dir, buttons, true);
    switch (a.id) {
    case 100:
        return Install(o, dir);
    case 101:
        return Rollback(o, dir);
    case 102:
        return ConfirmUninstall(o, dir);
    default:
        return kExitCancelled;
    }
}

Options ParseArguments()
{
    Options o;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; argv && i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--install") {
            o.action = Action::Install;
        } else if (arg == L"--rollback") {
            o.action = Action::Rollback;
        } else if (arg == L"--uninstall") {
            o.action = Action::Uninstall;
        } else if (arg == L"--cleanup") {
            o.action = Action::Cleanup;
        } else if (arg == L"--dir" && i + 1 < argc) {
            o.dir = argv[++i];
        } else if (arg == L"--wait" && i + 1 < argc) {
            o.waitPid = static_cast<DWORD>(_wtoi(argv[++i]));
        } else if (arg == L"--silent") {
            o.silent = true;
        } else if (arg == L"--no-shortcuts") {
            o.noShortcuts = true;
        } else if (arg == L"--remove-settings") {
            o.removeSettings = true;
        } else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            o.help = true;
        } else if (o.bad.empty()) {
            o.bad = arg;
        }
    }
    if (argv) {
        LocalFree(argv);
    }
    while (o.dir.size() > 3 && (o.dir.back() == L'\\' || o.dir.back() == L'/')) {
        o.dir.pop_back();
    }
    return o;
}

constexpr wchar_t kUsage[] =
    L"approute-setup — установка, обновление, откат и удаление AppRoute.\n\n"
    L"Без параметров — окно установки.\n\n"
    L"--install [--dir ПАПКА] [--no-shortcuts]\n"
    L"--rollback [--dir ПАПКА]\n"
    L"--uninstall [--dir ПАПКА] [--remove-settings]\n"
    L"--silent — без окон (служба AppRoute обновляется, только если установщик запущен от администратора)\n\n"
    L"Папка по умолчанию — %LOCALAPPDATA%\\Programs\\AppRoute.\n"
    L"Коды выхода: 0 — готово, 1 — ошибка, 2 — отменено или нечего делать.\n"
    L"Журнал — %TEMP%\\approute-setup.log.";

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    Options o = ParseArguments();
    if (o.help || !o.bad.empty()) {
        if (!o.silent) {
            Show(o.bad.empty() ? TD_INFORMATION_ICON : TD_WARNING_ICON,
                 o.bad.empty() ? L"Параметры установщика" : L"Неизвестный параметр: " + o.bad, kUsage);
        }
        return o.bad.empty() ? kExitOk : kExitError;
    }
    if (o.action == Action::Cleanup) {
        return o.dir.empty() ? kExitError : Cleanup(o);
    }

    // Один установщик за раз
    const HANDLE single = CreateMutexW(nullptr, FALSE, L"Local\\AppRoute.Setup");
    if (single && GetLastError() == ERROR_ALREADY_EXISTS) {
        Log(L"Установщик AppRoute уже запущен");
        if (!o.silent) {
            Show(TD_INFORMATION_ICON, L"Установщик AppRoute уже запущен", L"");
        }
        return kExitCancelled;
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    const std::wstring dir =
        !o.dir.empty() ? o.dir : RegisteredInstallDirectory().value_or(DefaultUserInstallDirectory());
    int code = kExitError;
    switch (o.action) {
    case Action::Menu:
        code = o.silent ? Install(o, dir) : Menu(o, dir);
        break;
    case Action::Install:
        code = Install(o, dir);
        break;
    case Action::Rollback:
        code = Rollback(o, dir);
        break;
    case Action::Uninstall:
        if (InspectInstallDirectory(dir) == InstallDirState::Missing && !RegisteredInstallDirectory()) {
            Log(L"Удаление: AppRoute не установлен в " + dir);
            if (!o.silent) {
                Show(TD_INFORMATION_ICON, L"AppRoute не установлен", L"Папка: " + dir);
            }
            code = kExitCancelled;
        } else {
            code = ConfirmUninstall(o, dir);
        }
        break;
    case Action::Cleanup:
        break;
    }
    Log(std::format(L"Код выхода {}", code));
    CoUninitialize();
    if (single) {
        CloseHandle(single);
    }
    return code;
}
