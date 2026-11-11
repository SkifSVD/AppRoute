#include "core/Setup.h"

#include "core/Autostart.h"
#include "core/Config.h"
#include "core/Launcher.h"
#include "core/Shortcuts.h"
#include "core/Util.h"

#include <shellapi.h>
#include <shlobj.h>
#include <wincred.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <format>
#include <memory>

namespace approute {

namespace fs = std::filesystem;

namespace {

bool Fail(SetupReport* report, std::wstring message)
{
    if (report) {
        report->error = std::move(message);
    }
    return false;
}

void Note(SetupReport* report, std::wstring message)
{
    if (report) {
        report->notes.push_back(std::move(message));
    }
}

std::wstring KnownFolderPath(REFKNOWNFOLDERID id)
{
    PWSTR path = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &path))) {
        out = path;
    }
    CoTaskMemFree(path);
    return out;
}

std::wstring Join(const std::wstring& dir, std::wstring_view name)
{
    std::wstring out = dir;
    if (!out.empty() && out.back() != L'\\' && out.back() != L'/') {
        out += L'\\';
    }
    out += name;
    return out;
}

// Путь без завершающей черты, для сравнения
std::wstring Normalized(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'/', L'\\');
    while (path.size() > 3 && path.back() == L'\\') {
        path.pop_back();
    }
    return path;
}

// path лежит в dir (или равен ей)
bool IsInside(const std::wstring& path, const std::wstring& dir)
{
    const std::wstring p = Normalized(path);
    const std::wstring d = Normalized(dir);
    if (p.size() < d.size() || !EqualsIgnoreCase(std::wstring_view(p).substr(0, d.size()), d)) {
        return false;
    }
    return p.size() == d.size() || p[d.size()] == L'\\';
}

bool WriteAll(const std::wstring& path, std::span<const std::byte> data)
{
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool ok = true;
    size_t offset = 0;
    while (ok && offset < data.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - offset, 1 << 20));
        DWORD written = 0;
        ok = WriteFile(h, data.data() + offset, chunk, &written, nullptr) && written == chunk;
        offset += chunk;
    }
    ok = CloseHandle(h) && ok;
    if (!ok) {
        DeleteFileW(path.c_str());
    }
    return ok;
}

std::optional<std::string> ReadSmallFile(const std::wstring& path)
{
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    char buf[256] = {};
    DWORD read = 0;
    const BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr);
    CloseHandle(h);
    if (!ok) {
        return std::nullopt;
    }
    return std::string(buf, read);
}

std::wstring Trim(std::wstring s)
{
    while (!s.empty() && std::iswspace(s.back())) {
        s.pop_back();
    }
    size_t start = 0;
    while (start < s.size() && std::iswspace(s[start])) {
        ++start;
    }
    return s.substr(start);
}

// Имена в папке установки, кроме резервных копий
std::vector<std::wstring> InstalledEntries(const std::wstring& dir)
{
    std::vector<std::wstring> out;
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::wstring name = it->path().filename().wstring();
        if (!EqualsIgnoreCase(name, kBackupSubdir)) {
            out.push_back(name);
        }
    }
    return out;
}

struct MovedFile {
    std::wstring from;
    std::wstring to;
};

// Перенос по файлам: занятый exe или DLL (в том числе работающий установщик в setup\) Windows
// переименовать разрешает, а папку с ним — нет. Папки создаются в to, опустевшие исходные удаляются.
bool MoveTree(const std::wstring& from, const std::wstring& to, std::vector<MovedFile>* moved, std::wstring* failed)
{
    const DWORD attributes = GetFileAttributesW(from.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (!CreateDirectoryW(to.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            if (failed) {
                *failed = std::format(L"{}: {}", to, Win32ErrorMessage(GetLastError()));
            }
            return false;
        }
        std::vector<std::wstring> children;
        std::error_code ec;
        for (fs::directory_iterator it(from, ec), end; !ec && it != end; it.increment(ec)) {
            children.push_back(it->path().filename().wstring());
        }
        for (const auto& child : children) {
            if (!MoveTree(Join(from, child), Join(to, child), moved, failed)) {
                return false;
            }
        }
        RemoveDirectoryW(from.c_str());   // не удалилась (текущая папка процесса) — не страшно
        return true;
    }
    if (MoveFileExW(from.c_str(), to.c_str(), 0)) {
        moved->push_back({from, to});
        return true;
    }
    if (failed) {
        *failed = std::format(L"{}: {}", from, Win32ErrorMessage(GetLastError()));
    }
    return false;
}

// Перенести записи names из папки from в папку to (на одном томе — переименование). Ошибка —
// уже перенесённое возвращается назад.
bool MoveEntries(const std::wstring& from, const std::wstring& to, const std::vector<std::wstring>& names,
                 std::wstring* failed)
{
    std::vector<MovedFile> moved;
    for (const auto& name : names) {
        if (MoveTree(Join(from, name), Join(to, name), &moved, failed)) {
            continue;
        }
        for (auto it = moved.rbegin(); it != moved.rend(); ++it) {
            std::error_code ec;
            fs::create_directories(fs::path(it->from).parent_path(), ec);
            MoveFileExW(it->to.c_str(), it->from.c_str(), 0);
        }
        return false;
    }
    return true;
}

// Удалить всё, что получится; не удалённое — в leftovers
void RemoveTree(const fs::path& path, std::vector<std::wstring>* leftovers)
{
    std::error_code ec;
    if (fs::is_directory(fs::symlink_status(path, ec))) {
        for (fs::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) {
            RemoveTree(it->path(), leftovers);
        }
    }
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    std::error_code removeError;
    fs::remove(path, removeError);
    // Непустая папка — из-за занятых файлов внутри, они уже в списке
    std::error_code statusError;
    if (removeError && leftovers && !fs::is_directory(fs::symlink_status(path, statusError))) {
        leftovers->push_back(path.wstring());
    }
}

// Метка резервной копии: время с миллисекундами — копии сортируются по имени
std::wstring BackupName(const std::wstring& backupRoot, std::wstring_view version)
{
    SYSTEMTIME t{};
    GetLocalTime(&t);
    const std::wstring stamp = std::format(L"{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}", t.wYear, t.wMonth, t.wDay, t.wHour,
                                           t.wMinute, t.wSecond, t.wMilliseconds);
    std::wstring name = std::format(L"{}_{}", stamp, version.empty() ? L"unknown" : version);
    for (int i = 2; GetFileAttributesW(Join(backupRoot, name).c_str()) != INVALID_FILE_ATTRIBUTES; ++i) {
        name = std::format(L"{}-{}_{}", stamp, i, version.empty() ? L"unknown" : version);
    }
    return name;
}

// Текущие файлы установки — в новую резервную копию; путь копии или nullopt
std::optional<std::wstring> BackupCurrent(const std::wstring& dir, SetupReport* report)
{
    const std::wstring root = Join(dir, kBackupSubdir);
    CreateDirectoryW(root.c_str(), nullptr);
    SetFileAttributesW(root.c_str(), FILE_ATTRIBUTE_HIDDEN);
    const std::wstring backup = Join(root, BackupName(root, InstalledVersion(dir).value_or(L"")));
    if (!CreateDirectoryW(backup.c_str(), nullptr)) {
        Fail(report, L"не удалось создать резервную копию " + backup + L": " + Win32ErrorMessage(GetLastError()));
        return std::nullopt;
    }
    std::wstring failed;
    if (!MoveEntries(dir, backup, InstalledEntries(dir), &failed)) {
        RemoveTree(fs::path(backup), nullptr);   // остались только пустые папки
        Fail(report, L"не удалось перенести в резервную копию " + failed);
        return std::nullopt;
    }
    return backup;
}

// Вернуть файлы из резервной копии на место (папка установки должна быть очищена)
bool RestoreBackup(const std::wstring& dir, const std::wstring& backup, std::wstring* failed)
{
    std::vector<std::wstring> names;
    std::error_code ec;
    for (fs::directory_iterator it(backup, ec), end; !ec && it != end; it.increment(ec)) {
        names.push_back(it->path().filename().wstring());
    }
    if (!MoveEntries(backup, dir, names, failed)) {
        return false;
    }
    RemoveTree(fs::path(backup), nullptr);
    return true;
}

// Удалить из папки установки всё, кроме резервных копий
void ClearInstalled(const std::wstring& dir)
{
    for (const auto& name : InstalledEntries(dir)) {
        RemoveTree(fs::path(Join(dir, name)), nullptr);
    }
}

void PruneBackups(const std::wstring& dir, SetupReport* report)
{
    const auto backups = ListBackups(dir);
    for (size_t i = kBackupsKept; i < backups.size(); ++i) {
        std::vector<std::wstring> leftovers;
        RemoveTree(fs::path(backups[i].path), &leftovers);
        if (!leftovers.empty()) {
            Note(report, std::format(L"Старая копия {} удалится при следующем обновлении: файлы заняты запущенными "
                                     L"программами.",
                                     backups[i].version));
        }
    }
}

} // namespace

std::wstring DefaultUserInstallDirectory()
{
    std::wstring local = KnownFolderPath(FOLDERID_LocalAppData);
    if (local.empty()) {
        wchar_t buf[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) > 0) {
            local = buf;
        }
    }
    return local + L"\\Programs\\AppRoute";
}

int CompareVersions(std::wstring_view a, std::wstring_view b)
{
    auto parts = [](std::wstring_view v) {
        std::vector<unsigned long> out;
        size_t start = 0;
        while (start <= v.size() && out.size() < 4) {
            size_t end = v.find(L'.', start);
            if (end == std::wstring_view::npos) {
                end = v.size();
            }
            unsigned long n = 0;
            for (wchar_t c : v.substr(start, end - start)) {
                if (c < L'0' || c > L'9') {
                    break;
                }
                n = n * 10 + static_cast<unsigned long>(c - L'0');
            }
            out.push_back(n);
            start = end + 1;
        }
        out.resize(4, 0);
        return out;
    };
    const auto pa = parts(a);
    const auto pb = parts(b);
    for (size_t i = 0; i < pa.size(); ++i) {
        if (pa[i] != pb[i]) {
            return pa[i] < pb[i] ? -1 : 1;
        }
    }
    return 0;
}

std::optional<std::wstring> InstalledVersion(const std::wstring& dir)
{
    const auto text = ReadSmallFile(Join(dir, kInstallMarker));
    if (!text) {
        return std::nullopt;
    }
    return Trim(FromUtf8(*text).value_or(L""));
}

InstallDirState InspectInstallDirectory(const std::wstring& dir)
{
    const DWORD attributes = GetFileAttributesW(dir.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return InstallDirState::Missing;
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return InstallDirState::Foreign;
    }
    if (InstalledVersion(dir)) {
        return InstallDirState::Installed;
    }
    std::error_code ec;
    return fs::is_empty(dir, ec) && !ec ? InstallDirState::Empty : InstallDirState::Foreign;
}

std::vector<BackupInfo> ListBackups(const std::wstring& dir)
{
    std::vector<BackupInfo> out;
    std::error_code ec;
    for (fs::directory_iterator it(Join(dir, kBackupSubdir), ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec)) {
            continue;
        }
        BackupInfo info;
        info.path = it->path().wstring();
        if (const auto version = InstalledVersion(info.path)) {
            info.version = *version;
        } else {
            continue;   // не копия установки (или копия, удалённая не до конца)
        }
        out.push_back(std::move(info));
    }
    std::sort(out.begin(), out.end(), [](const BackupInfo& a, const BackupInfo& b) {
        return fs::path(a.path).filename().wstring() > fs::path(b.path).filename().wstring();
    });
    return out;
}

bool InstallFiles(const std::wstring& dir, const std::vector<PayloadFile>& files, std::wstring_view version,
                  std::span<const std::byte> setupImage, SetupReport* report)
{
    const InstallDirState state = InspectInstallDirectory(dir);
    if (state == InstallDirState::Foreign) {
        return Fail(report, L"папка " + dir + L" не пуста и не содержит установку AppRoute — выберите другую");
    }
    if (state == InstallDirState::Missing) {
        std::error_code ec;
        fs::create_directories(dir, ec);
        if (ec) {
            return Fail(report, L"не удалось создать папку " + dir);
        }
    }

    std::optional<std::wstring> backup;
    if (state == InstallDirState::Installed) {
        backup = BackupCurrent(dir, report);
        if (!backup) {
            return false;
        }
    }

    // Ошибка записи — убрать записанное и вернуть прежние файлы
    auto undo = [&](std::wstring message) {
        ClearInstalled(dir);
        std::wstring failed;
        if (backup && !RestoreBackup(dir, *backup, &failed)) {
            message += L". Прежняя версия осталась в " + *backup;
        }
        return Fail(report, std::move(message));
    };

    for (const PayloadFile& file : files) {
        if (file.name.empty() || file.name.find_first_of(L"\\/:") != std::wstring::npos) {
            return undo(L"недопустимое имя файла в установщике: " + file.name);
        }
        if (!WriteAll(Join(dir, file.name), file.data)) {
            return undo(L"не удалось записать " + Join(dir, file.name) + L": " + Win32ErrorMessage(GetLastError()));
        }
    }
    if (!setupImage.empty()) {
        const std::wstring setupDir = Join(dir, kSetupSubdir);
        CreateDirectoryW(setupDir.c_str(), nullptr);
        if (!WriteAll(Join(setupDir, kSetupExeName), setupImage)) {
            return undo(L"не удалось записать копию установщика: " + Win32ErrorMessage(GetLastError()));
        }
    }
    const std::string marker = ToUtf8(version);
    if (!WriteAll(Join(dir, kInstallMarker), std::as_bytes(std::span(marker.data(), marker.size())))) {
        return undo(L"не удалось записать отметку установки: " + Win32ErrorMessage(GetLastError()));
    }
    SetFileAttributesW(Join(dir, kInstallMarker).c_str(), FILE_ATTRIBUTE_HIDDEN);

    PruneBackups(dir, report);
    return true;
}

std::optional<std::wstring> RollbackFiles(const std::wstring& dir, SetupReport* report)
{
    if (InspectInstallDirectory(dir) != InstallDirState::Installed) {
        Fail(report, L"в папке " + dir + L" нет установки AppRoute");
        return std::nullopt;
    }
    const auto backups = ListBackups(dir);
    if (backups.empty()) {
        Fail(report, L"нет сохранённой предыдущей версии");
        return std::nullopt;
    }
    const BackupInfo target = backups.front();
    const auto current = BackupCurrent(dir, report);
    if (!current) {
        return std::nullopt;
    }
    std::wstring failed;
    if (!RestoreBackup(dir, target.path, &failed)) {
        ClearInstalled(dir);   // перенесённое частично вернулось в копию, остальное — убрать
        std::wstring ignored;
        RestoreBackup(dir, *current, &ignored);
        Fail(report, L"не удалось вернуть файлы из копии: " + failed);
        return std::nullopt;
    }
    PruneBackups(dir, report);
    return target.version;
}

bool RemoveInstallFiles(const std::wstring& dir, SetupReport* report)
{
    if (InspectInstallDirectory(dir) != InstallDirState::Installed) {
        return Fail(report, L"в папке " + dir + L" нет установки AppRoute");
    }
    std::vector<std::wstring> leftovers;
    // Отметку — последней: пока она есть, папку можно удалить повторно
    for (const auto& name : InstalledEntries(dir)) {
        if (!EqualsIgnoreCase(name, kInstallMarker)) {
            RemoveTree(fs::path(Join(dir, name)), &leftovers);
        }
    }
    RemoveTree(fs::path(Join(dir, kBackupSubdir)), &leftovers);
    if (!leftovers.empty()) {
        for (const auto& file : leftovers) {
            Note(report, L"Не удалён (занят): " + file);
        }
        return false;
    }
    DeleteFileW(Join(dir, kInstallMarker).c_str());
    RemoveDirectoryW(dir.c_str());
    return true;
}

// --- запись в «Приложениях» -----------------------------------------------------------------

std::vector<RegistryValue> UninstallValues(const std::wstring& dir, std::wstring_view version, DWORD sizeKb,
                                           std::wstring_view installDate)
{
    // Путь — всегда в кавычках: так «Приложения» надёжно отделяют его от параметров
    const std::wstring setup = L"\"" + Join(Join(dir, kSetupSubdir), kSetupExeName) + L"\"";
    return {
        {L"DisplayName", std::wstring(L"AppRoute")},
        {L"DisplayVersion", std::wstring(version)},
        {L"Publisher", std::wstring(L"AppRoute")},
        {L"DisplayIcon", Join(dir, L"approute-gui.exe") + L",0"},
        {L"InstallLocation", dir},
        {L"InstallDate", std::wstring(installDate)},
        {L"URLInfoAbout", std::wstring(L"https://github.com/SkifSVD/AppRoute")},
        {L"UninstallString", setup + L" --uninstall"},
        {L"QuietUninstallString", setup + L" --uninstall --silent"},
        {L"ModifyPath", setup},   // «Изменить»: меню установщика — переустановка, откат, удаление
        {L"NoRepair", DWORD{1}},
        {L"EstimatedSize", sizeKb},
    };
}

DWORD InstallSizeKb(const std::wstring& dir)
{
    uintmax_t total = 0;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        if (it->is_directory(ec) && EqualsIgnoreCase(it->path().filename().wstring(), kBackupSubdir)) {
            it.disable_recursion_pending();
            continue;
        }
        if (it->is_regular_file(ec)) {
            total += it->file_size(ec);
        }
    }
    return static_cast<DWORD>(total / 1024);
}

bool WriteUninstallEntry(const std::wstring& dir, std::wstring_view version, std::wstring* error)
{
    SYSTEMTIME t{};
    GetLocalTime(&t);
    HKEY key = nullptr;
    LSTATUS rc = RegCreateKeyExW(HKEY_CURRENT_USER, kUninstallKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (rc != ERROR_SUCCESS) {
        if (error) {
            *error = L"не удалось создать запись в «Приложениях»: " + Win32ErrorMessage(rc);
        }
        return false;
    }
    for (const RegistryValue& v : UninstallValues(dir, version, InstallSizeKb(dir),
                                                  std::format(L"{:04}{:02}{:02}", t.wYear, t.wMonth, t.wDay))) {
        if (const auto* s = std::get_if<std::wstring>(&v.value)) {
            rc = RegSetValueExW(key, v.name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(s->c_str()),
                                static_cast<DWORD>((s->size() + 1) * sizeof(wchar_t)));
        } else {
            const DWORD d = std::get<DWORD>(v.value);
            rc = RegSetValueExW(key, v.name.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&d), sizeof(d));
        }
        if (rc != ERROR_SUCCESS) {
            break;
        }
    }
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS && error) {
        *error = L"не удалось записать запись в «Приложениях»: " + Win32ErrorMessage(rc);
    }
    return rc == ERROR_SUCCESS;
}

void RemoveUninstallEntry()
{
    RegDeleteTreeW(HKEY_CURRENT_USER, kUninstallKey);
    RegDeleteKeyW(HKEY_CURRENT_USER, kUninstallKey);
}

std::optional<std::wstring> RegisteredInstallDirectory()
{
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_CURRENT_USER, kUninstallKey, L"InstallLocation", RRF_RT_REG_SZ, nullptr, buf, &size) !=
            ERROR_SUCCESS ||
        !buf[0]) {
        return std::nullopt;
    }
    return std::wstring(buf);
}

// --- интеграция с оболочкой -----------------------------------------------------------------

std::wstring StartMenuShortcutPath()
{
    return KnownFolderPath(FOLDERID_Programs) + L"\\AppRoute.lnk";
}

bool CreateStartMenuShortcut(const std::wstring& dir, std::wstring* error)
{
    ShortcutSpec spec;
    spec.target = Join(dir, L"approute-gui.exe");
    spec.workingDirectory = dir;
    spec.iconPath = spec.target;
    spec.description = L"AppRoute — маршрутизация трафика по приложениям";
    return SaveShortcut(StartMenuShortcutPath(), spec, error);
}

void RemoveUserShortcuts(const std::wstring& dir)
{
    const std::wstring gui = Join(dir, L"approute-gui.exe");
    auto ours = [&](const fs::path& lnk) {
        const auto spec = ReadShortcut(lnk.wstring());
        return spec && EqualsIgnoreCase(Normalized(spec->target), Normalized(gui));
    };
    std::error_code ec;
    if (ours(StartMenuShortcutPath())) {
        fs::remove(StartMenuShortcutPath(), ec);
    }
    // Ярлыки программ, созданные в окне правил (#13): папка AppRoute в меню «Пуск» и рабочий стол
    const fs::path startFolder = KnownFolderPath(FOLDERID_Programs) + L"\\AppRoute";
    for (const fs::path& folder : {startFolder, fs::path(KnownFolderPath(FOLDERID_Desktop))}) {
        for (fs::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec)) {
            if (EqualsIgnoreCase(it->path().extension().wstring(), L".lnk") && ours(it->path())) {
                std::error_code ignored;
                fs::remove(it->path(), ignored);
            }
        }
        ec.clear();
    }
    RemoveDirectoryW(startFolder.c_str());   // только пустую
}

void RemoveAutostartFor(const std::wstring& dir)
{
    const auto command = ReadAutostartEntry();
    if (!command || !IsInside(ProgramOfCommand(*command), dir)) {
        return;
    }
    RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", kAutostartValueName);
    RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
                       kAutostartValueName);
}

void RemoveUserSettings(SetupReport* report)
{
    std::vector<std::wstring> leftovers;
    const fs::path configDir = fs::path(DefaultConfigPath()).parent_path();
    if (EqualsIgnoreCase(configDir.filename().wstring(), L"AppRoute")) {
        RemoveTree(configDir, &leftovers);
    }
    const std::wstring local = KnownFolderPath(FOLDERID_LocalAppData);
    if (!local.empty()) {
        RemoveTree(fs::path(local + L"\\AppRoute"), &leftovers);
    }
    for (const auto& file : leftovers) {
        Note(report, L"Не удалён (занят): " + file);
    }

    DWORD count = 0;
    PCREDENTIALW* creds = nullptr;
    if (CredEnumerateW(L"AppRoute/*", 0, &count, &creds)) {
        for (DWORD i = 0; i < count; ++i) {
            CredDeleteW(creds[i]->TargetName, creds[i]->Type, 0);
        }
        CredFree(creds);
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\AppRoute");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\AppRoute");
}

namespace {

// Командная строка другого процесса того же пользователя (Windows 8.1+, ProcessCommandLineInformation)
std::wstring ProcessCommandLine(HANDLE process)
{
    using QueryFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<QueryFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));
    constexpr ULONG kProcessCommandLineInformation = 60;
    if (!query) {
        return {};
    }
    ULONG size = 0;
    query(process, kProcessCommandLineInformation, nullptr, 0, &size);
    if (size < sizeof(UNICODE_STRING) || size > 1 << 20) {
        return {};
    }
    std::vector<BYTE> buf(size);
    if (query(process, kProcessCommandLineInformation, buf.data(), size, &size) < 0) {
        return {};
    }
    const auto* text = reinterpret_cast<const UNICODE_STRING*>(buf.data());
    return text->Buffer ? std::wstring(text->Buffer, text->Length / sizeof(wchar_t)) : std::wstring();
}

} // namespace

bool CloseRunningGui(const std::wstring& dir, DWORD waitMs, bool* wasRunning, std::wstring* arguments)
{
    if (wasRunning) {
        *wasRunning = false;
    }
    const HWND window = FindWindowW(L"#32770", kGuiWindowTitle);
    if (!window) {
        return true;
    }
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    const HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return false;
    }
    wchar_t image[MAX_PATH * 2] = {};
    DWORD size = static_cast<DWORD>(std::size(image));
    if (!QueryFullProcessImageNameW(process, 0, image, &size) || !IsInside(image, dir)) {
        CloseHandle(process);
        return true;   // окно другой копии AppRoute — не наше дело
    }
    if (wasRunning) {
        *wasRunning = true;
    }
    if (arguments) {
        *arguments = ArgumentsAfterProgram(ProcessCommandLine(process));
    }
    PostMessageW(window, RegisterWindowMessageW(kGuiExitMessage), 0, 0);
    const bool closed = WaitForSingleObject(process, waitMs) == WAIT_OBJECT_0;
    CloseHandle(process);
    return closed;
}

// --- служба AppRoute ------------------------------------------------------------------------

std::optional<ServiceSetupArgs> ParseServiceCommand(std::wstring_view commandLine)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(std::wstring(commandLine).c_str(), &argc);
    if (!argv) {
        return std::nullopt;
    }
    ServiceSetupArgs out;
    for (int i = 1; i + 1 < argc; ++i) {
        if (EqualsIgnoreCase(argv[i], L"--config")) {
            out.config = argv[++i];
        } else if (EqualsIgnoreCase(argv[i], L"--client-sid")) {
            out.clientSid = argv[++i];
        }
    }
    LocalFree(argv);
    if (out.config.empty() || out.clientSid.empty()) {
        return std::nullopt;
    }
    return out;
}

std::optional<std::wstring> InstalledServiceCommand()
{
    struct Sc {
        SC_HANDLE h;
        ~Sc() { if (h) CloseServiceHandle(h); }
    };
    Sc scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    Sc service{scm.h ? OpenServiceW(scm.h, L"AppRoute", SERVICE_QUERY_CONFIG) : nullptr};
    if (!service.h) {
        return std::nullopt;
    }
    DWORD needed = 0;
    QueryServiceConfigW(service.h, nullptr, 0, &needed);
    if (needed == 0) {
        return std::nullopt;
    }
    std::vector<BYTE> buf(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
    if (!QueryServiceConfigW(service.h, config, needed, &needed) || !config->lpBinaryPathName) {
        return std::nullopt;
    }
    return std::wstring(config->lpBinaryPathName);
}

std::wstring ServiceReinstallParameters(const ServiceSetupArgs& args, bool withDriver)
{
    return L"install-service --config " + QuoteArgument(args.config) + L" --client-sid " +
           QuoteArgument(args.clientSid) + (withDriver ? L" --with-driver" : L"");
}

} // namespace approute
