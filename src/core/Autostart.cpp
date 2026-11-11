#include "core/Autostart.h"

#include "core/NetAdapters.h"
#include "core/PackagedApps.h"
#include "core/ProxyCredentials.h"
#include "core/Shortcuts.h"
#include "core/Socks5.h"
#include "core/Util.h"

#include <shlobj.h>

#include <format>

namespace approute {

namespace {

constexpr wchar_t kRunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRun32Key[] = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kApprovedKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\";

std::wstring ExpandEnv(std::wstring_view s)
{
    const std::wstring in(s);
    const DWORD n = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (n == 0) {
        return in;
    }
    std::wstring out(n, L'\0');
    const DWORD m = ExpandEnvironmentStringsW(in.c_str(), out.data(), n);
    out.resize(m > 0 ? m - 1 : 0);
    return out;
}

std::optional<std::wstring> ReadString(HKEY root, const wchar_t* subkey, const wchar_t* name)
{
    DWORD size = 0;
    if (RegGetValueW(root, subkey, name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, nullptr,
                     &size) != ERROR_SUCCESS ||
        size == 0) {
        return std::nullopt;
    }
    std::wstring value(size / sizeof(wchar_t), L'\0');
    if (RegGetValueW(root, subkey, name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr,
                     value.data(), &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    value.resize(wcslen(value.c_str()));
    return value;
}

// «Параметры → Автозагрузка» хранят отключение в StartupApproved: первый байт нечётный — отключено
bool Approved(HKEY root, const wchar_t* list, const std::wstring& name)
{
    BYTE data[16] = {};
    DWORD size = sizeof(data);
    const std::wstring key = std::wstring(kApprovedKey) + list;
    if (RegGetValueW(root, key.c_str(), name.c_str(), RRF_RT_REG_BINARY, nullptr, data, &size) != ERROR_SUCCESS ||
        size == 0) {
        return true;
    }
    return (data[0] & 1) == 0;
}

struct RunEntry {
    std::wstring name;
    std::wstring command;
};

std::vector<RunEntry> RunEntries(HKEY root, const wchar_t* subkey)
{
    std::vector<RunEntry> out;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return out;
    }
    for (DWORD i = 0;; ++i) {
        wchar_t name[512];
        DWORD nameLength = static_cast<DWORD>(std::size(name));
        DWORD type = 0;
        DWORD size = 0;
        const LSTATUS rc = RegEnumValueW(key, i, name, &nameLength, nullptr, &type, nullptr, &size);
        if (rc == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            continue;
        }
        if (auto command = ReadString(key, nullptr, name)) {
            out.push_back({name, std::move(*command)});
        }
    }
    RegCloseKey(key);
    return out;
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

} // namespace

std::wstring AutostartCommand(const std::wstring& guiExe, const std::wstring& configPath)
{
    std::wstring command = L"\"" + guiExe + L"\"";
    if (!configPath.empty() && !EqualsIgnoreCase(configPath, DefaultConfigPath())) {
        command += L" --config " + QuoteArgument(configPath);
    }
    return command + L" --autostart";
}

bool AutostartWanted(const Config& config)
{
    for (const Rule& rule : config.rules) {
        if (rule.autostart) {
            return true;
        }
    }
    return false;
}

std::optional<std::wstring> ReadAutostartEntry()
{
    return ReadString(HKEY_CURRENT_USER, kRunKey, kAutostartValueName);
}

bool SyncAutostart(const Config& config, const std::wstring& guiExe, const std::wstring& configPath,
                   std::wstring* error)
{
    const auto fail = [&](LSTATUS rc) {
        if (error) {
            *error = L"Автозапуск AppRoute: " + Win32ErrorMessage(static_cast<DWORD>(rc));
        }
        return false;
    };
    const auto current = ReadAutostartEntry();
    if (!AutostartWanted(config)) {
        if (!current) {
            return true;
        }
        const LSTATUS rc = RegDeleteKeyValueW(HKEY_CURRENT_USER, kRunKey, kAutostartValueName);
        return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND ? true : fail(rc);
    }
    const std::wstring command = AutostartCommand(guiExe, configPath);
    if (current && *current == command) {
        return true;
    }
    const LSTATUS rc = RegSetKeyValueW(HKEY_CURRENT_USER, kRunKey, kAutostartValueName, REG_SZ, command.c_str(),
                                       static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    return rc == ERROR_SUCCESS ? true : fail(rc);
}

std::wstring ProgramOfCommand(std::wstring_view command)
{
    while (!command.empty() && (command.front() == L' ' || command.front() == L'\t')) {
        command.remove_prefix(1);
    }
    std::wstring_view program;
    if (!command.empty() && command.front() == L'"') {
        const auto end = command.find(L'"', 1);
        program = command.substr(1, end == std::wstring_view::npos ? std::wstring_view::npos : end - 1);
    } else {
        // Без кавычек путь может содержать пробелы: до ".exe", иначе до первого пробела
        std::wstring lower(command);
        for (auto& c : lower) {
            c = static_cast<wchar_t>(towlower(c));
        }
        const auto exe = lower.find(L".exe");
        program = exe != std::wstring::npos ? command.substr(0, exe + 4)
                                            : command.substr(0, command.find_first_of(L" \t"));
    }
    return ExpandEnv(program);
}

bool CommandMatchesRule(const Rule& rule, std::wstring_view command)
{
    if (IsPackageApp(rule.app)) {
        return false;
    }
    const std::wstring program = ProgramOfCommand(command);
    if (program.empty()) {
        return false;
    }
    Config single;
    single.rules = {rule};
    single.rules[0].app = ExpandEnv(rule.app);
    return FindRule(single, program) != nullptr;
}

std::vector<std::wstring> FindOwnAutostart(const Rule& rule)
{
    std::vector<std::wstring> found;
    if (IsPackageApp(rule.app)) {
        return found;
    }
    struct Source {
        HKEY root;
        const wchar_t* key;
        const wchar_t* approved;
        const wchar_t* title;
    };
    const Source sources[] = {
        {HKEY_CURRENT_USER, kRunKey, L"Run", L"автозагрузка текущего пользователя"},
        {HKEY_LOCAL_MACHINE, kRunKey, L"Run", L"автозагрузка всех пользователей"},
        {HKEY_LOCAL_MACHINE, kRun32Key, L"Run32", L"автозагрузка всех пользователей"},
    };
    for (const Source& s : sources) {
        for (const RunEntry& e : RunEntries(s.root, s.key)) {
            if (s.root == HKEY_CURRENT_USER && EqualsIgnoreCase(e.name, kAutostartValueName)) {
                continue;
            }
            if (CommandMatchesRule(rule, e.command) && Approved(s.root, s.approved, e.name)) {
                found.push_back(std::format(L"«{}» ({})", e.name, s.title));
            }
        }
    }
    struct Folder {
        REFKNOWNFOLDERID id;
        HKEY approvedRoot;
        const wchar_t* title;
    };
    const Folder folders[] = {
        {FOLDERID_Startup, HKEY_CURRENT_USER, L"папка «Автозагрузка»"},
        {FOLDERID_CommonStartup, HKEY_LOCAL_MACHINE, L"папка «Автозагрузка» всех пользователей"},
    };
    for (const Folder& f : folders) {
        const std::wstring dir = KnownFolderPath(f.id);
        if (dir.empty()) {
            continue;
        }
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW((dir + L"\\*.lnk").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) {
            continue;
        }
        do {
            const auto link = ReadShortcut(dir + L"\\" + data.cFileName);
            if (link && CommandMatchesRule(rule, L"\"" + link->target + L"\"") &&
                Approved(f.approvedRoot, L"StartupFolder", data.cFileName)) {
                found.push_back(std::format(L"«{}» ({})", data.cFileName, f.title));
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return found;
}

bool RuleTargetReady(const Rule& rule)
{
    if (!rule.proxy.empty()) {
        const auto address = ParseProxyAddress(rule.proxy);
        return address && CheckProxy(*address, nullptr, 1000) != Socks5Auth::NoAnswer;
    }
    try {
        const auto adapters = EnumerateAdapters();
        const NetAdapter* adapter = FindAdapter(adapters, rule.adapter);
        if (!adapter || !adapter->IsUp()) {
            return false;
        }
        for (const UnicastAddress& a : adapter->unicast) {
            if (a.address.si_family == AF_INET) {
                return true;
            }
        }
        return false;
    } catch (...) {
        return false;
    }
}

} // namespace approute
