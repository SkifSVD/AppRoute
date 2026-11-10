#include "core/InstalledApps.h"

#include "core/Com.h"
#include "core/Util.h"
#include "core/Win.h"

#include <msi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace approute {

namespace {

std::wstring Lower(std::wstring_view s)
{
    if (s.empty()) {
        return {};
    }
    std::wstring out(s.size(), L'\0');
    const int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(), static_cast<int>(s.size()),
                                out.data(), static_cast<int>(out.size()), nullptr, nullptr, 0);
    out.resize(n > 0 ? static_cast<size_t>(n) : 0);
    return n > 0 ? out : std::wstring(s);
}

bool EndsWithIgnoreCase(std::wstring_view s, std::wstring_view suffix)
{
    return s.size() >= suffix.size() && EqualsIgnoreCase(s.substr(s.size() - suffix.size()), suffix);
}

std::wstring_view FileNamePart(std::wstring_view path)
{
    const auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring_view::npos ? path : path.substr(pos + 1);
}

std::wstring ExpandEnv(const std::wstring& s)
{
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (n == 0) {
        return s;
    }
    std::wstring out(n, L'\0');
    const DWORD m = ExpandEnvironmentStringsW(s.c_str(), out.data(), n);
    out.resize(m > 0 ? m - 1 : 0);
    return out;
}

bool IsExistingExe(const std::wstring& path)
{
    if (!EndsWithIgnoreCase(path, L".exe")) {
        return false;
    }
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

// «Объявленный» ярлык установщика MSI (Office и т.п.): цель — компонент продукта
std::optional<std::wstring> MsiShortcutTarget(const std::wstring& lnkPath)
{
    wchar_t product[39] = {};
    wchar_t feature[MAX_FEATURE_CHARS + 1] = {};
    wchar_t component[39] = {};
    if (MsiGetShortcutTargetW(lnkPath.c_str(), product, feature, component) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    DWORD size = 0;
    MsiGetComponentPathW(product, component, nullptr, &size);
    std::wstring path(static_cast<size_t>(size) + 1, L'\0');
    size = static_cast<DWORD>(path.size());
    const INSTALLSTATE state = MsiGetComponentPathW(product, component, path.data(), &size);
    if (state != INSTALLSTATE_LOCAL) {
        return std::nullopt;
    }
    path.resize(size);
    return path;
}

std::optional<std::wstring> ShortcutTarget(const std::wstring& lnkPath)
{
    ComScope com;
    ComPtr<IShellLinkW> link;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)))) {
        return std::nullopt;
    }
    ComPtr<IPersistFile> file;
    if (FAILED(link->QueryInterface(IID_PPV_ARGS(&file))) || FAILED(file->Load(lnkPath.c_str(), STGM_READ))) {
        return std::nullopt;
    }
    ComPtr<IShellLinkDataList> data;
    DWORD flags = 0;
    if (SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&data))) && SUCCEEDED(data->GetFlags(&flags)) &&
        (flags & SLDF_HAS_DARWINID)) {
        return MsiShortcutTarget(lnkPath);
    }
    std::wstring target(32768, L'\0');
    if (link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH) != S_OK) {
        return std::nullopt;   // S_FALSE — ярлык не на файл (папка, URL, элемент оболочки)
    }
    target.resize(wcslen(target.c_str()));
    return ExpandEnv(target);
}

void AddShortcuts(const std::wstring& folder, std::vector<InstalledApp>& out)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::recursive_directory_iterator it(folder, fs::directory_options::skip_permission_denied, ec);
    for (const fs::recursive_directory_iterator end; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        if (!EqualsIgnoreCase(p.extension().wstring(), L".lnk")) {
            continue;
        }
        if (auto target = ResolveShortcut(p.wstring())) {
            out.push_back({p.stem().wstring(), std::move(*target)});
        }
    }
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

// HKxx\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\name.exe: (по умолчанию) = путь
void AddAppPaths(HKEY root, REGSAM view, std::vector<InstalledApp>& out)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", 0,
                      KEY_READ | view, &key) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0;; ++i) {
        wchar_t sub[256] = {};
        DWORD subLen = static_cast<DWORD>(std::size(sub));
        if (RegEnumKeyExW(key, i, sub, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }
        std::wstring value(1024, L'\0');
        DWORD bytes = static_cast<DWORD>(value.size() * sizeof(wchar_t));
        if (RegGetValueW(key, sub, nullptr, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr,
                         value.data(), &bytes) != ERROR_SUCCESS) {
            continue;
        }
        value.resize(wcslen(value.c_str()));
        // Путь бывает в кавычках
        if (value.size() >= 2 && value.front() == L'"') {
            value = value.substr(1, value.find(L'"', 1) - 1);
        }
        std::wstring path = ExpandEnv(value);
        if (!IsExistingExe(path)) {
            continue;
        }
        std::wstring name(FileNamePart(path));
        name.resize(name.size() - 4);   // без .exe
        out.push_back({std::move(name), std::move(path)});
    }
    RegCloseKey(key);
}

} // namespace

std::optional<std::wstring> ResolveShortcut(const std::wstring& lnkPath)
{
    auto target = ShortcutTarget(lnkPath);
    if (!target || !IsExistingExe(*target)) {
        return std::nullopt;
    }
    return target;
}

std::optional<std::wstring> ProgramFromFile(const std::wstring& path, std::wstring* error)
{
    const auto fail = [&](const wchar_t* message) -> std::optional<std::wstring> {
        if (error) {
            *error = message;
        }
        return std::nullopt;
    };
    if (EndsWithIgnoreCase(path, L".lnk")) {
        if (auto target = ResolveShortcut(path)) {
            return target;
        }
        return fail(L"Ярлык не указывает на программу (.exe) — например, это ярлык на папку, сайт "
                    L"или приложение Microsoft Store.");
    }
    if (!EndsWithIgnoreCase(path, L".exe")) {
        return fail(L"Нужен файл программы (.exe) или ярлык на неё (.lnk).");
    }
    if (!IsExistingExe(path)) {
        return fail(L"Файл программы не найден.");
    }
    return path;
}

std::vector<InstalledApp> EnumerateInstalledApps()
{
    ComScope com;   // один раз на все ярлыки
    std::vector<InstalledApp> apps;
    for (const auto& folder : {KnownFolder(FOLDERID_Programs), KnownFolder(FOLDERID_CommonPrograms)}) {
        if (!folder.empty()) {
            AddShortcuts(folder, apps);
        }
    }
    AddAppPaths(HKEY_CURRENT_USER, 0, apps);
    AddAppPaths(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, apps);
    AddAppPaths(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, apps);
    return MergeInstalledApps(std::move(apps));
}

bool IsUtilityShortcut(std::wstring_view name, std::wstring_view exePath)
{
    const std::wstring n = Lower(name);
    const std::wstring file = Lower(FileNamePart(exePath));
    for (const wchar_t* word : {L"uninstall", L"удал", L"деинстал", L"readme", L"справка", L"help", L"website"}) {
        if (n.find(word) != std::wstring::npos) {
            return true;
        }
    }
    // unins*.exe — деинсталляторы; approute-*.exe — ярлыки запуска самого AppRoute (#13)
    for (const wchar_t* prefix : {L"unins", L"uninst", L"uninstall", L"approute-"}) {
        if (file.starts_with(prefix)) {
            return true;
        }
    }
    // Служебные файлы установщика Windows (значки «объявленных» ярлыков) и приложения
    // Microsoft Store: их файлы в WindowsApps нельзя запустить напрямую, а значит и через AppRoute
    const std::wstring path = Lower(exePath);
    return path.find(L"\\windows\\installer\\") != std::wstring::npos ||
           path.find(L"\\windowsapps\\") != std::wstring::npos;
}

std::vector<InstalledApp> MergeInstalledApps(std::vector<InstalledApp> apps)
{
    std::vector<InstalledApp> out;
    for (auto& app : apps) {
        if (app.name.empty() || app.path.empty() || IsUtilityShortcut(app.name, app.path)) {
            continue;
        }
        const bool seen = std::any_of(out.begin(), out.end(),
                                      [&](const InstalledApp& o) { return EqualsIgnoreCase(o.path, app.path); });
        if (!seen) {
            out.push_back(std::move(app));
        }
    }
    std::stable_sort(out.begin(), out.end(), [](const InstalledApp& a, const InstalledApp& b) {
        return CompareStringEx(LOCALE_NAME_USER_DEFAULT, LINGUISTIC_IGNORECASE, a.name.c_str(), -1, b.name.c_str(),
                               -1, nullptr, nullptr, 0) == CSTR_LESS_THAN;
    });
    return out;
}

bool MatchesAppFilter(const InstalledApp& app, std::wstring_view query)
{
    const std::wstring haystack = Lower(app.name) + L"\n" + Lower(app.path);
    const std::wstring q = Lower(query);
    size_t pos = 0;
    while (pos < q.size()) {
        const size_t start = q.find_first_not_of(L' ', pos);
        if (start == std::wstring::npos) {
            break;
        }
        const size_t end = std::min(q.find(L' ', start), q.size());
        if (haystack.find(q.substr(start, end - start)) == std::wstring::npos) {
            return false;
        }
        pos = end;
    }
    return true;
}

} // namespace approute
