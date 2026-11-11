#include "core/Launcher.h"

#include "core/Com.h"
#include "core/PackagedApps.h"
#include "core/Process.h"
#include "core/Util.h"

#include <shobjidl.h>
#include <tlhelp32.h>

#include <format>
#include <vector>

namespace approute {

namespace {

// Правило для hook-DLL — переменные окружения процесса (пустое значение — удалить переменную)
EnvVars RuleEnvironment(const LaunchRequest& request)
{
    const wchar_t* onUnavailable = OnUnavailableEnvValue(request.policy.onUnavailable);
    const wchar_t* ipv6 = Ipv6EnvValue(request.policy.ipv6);
    EnvVars vars = {
        {kEnvAdapter, request.proxy.empty() ? request.adapterGuid : std::wstring()},
        {kEnvProxy, request.proxy},
        {kEnvLog, request.logPath},
        {kEnvChildren, request.includeChildren ? L"" : L"0"},
        {kEnvOnUnavailable, onUnavailable ? onUnavailable : L""},
        {kEnvIpv6, ipv6 ? ipv6 : L""},
    };
    if (request.systemDns) {
        vars.emplace_back(kEnvDns, L"system");   // иначе — как задано у пользователя
    }
    return vars;
}

} // namespace

std::wstring ArgumentsAfterProgram(std::wstring_view commandLine)
{
    size_t pos = 0;
    if (!commandLine.empty() && commandLine.front() == L'"') {
        pos = commandLine.find(L'"', 1);
        pos = pos == std::wstring_view::npos ? commandLine.size() : pos + 1;
    } else {
        pos = commandLine.find_first_of(L" \t");
        pos = pos == std::wstring_view::npos ? commandLine.size() : pos;
    }
    const auto start = commandLine.find_first_not_of(L" \t", pos);
    return start == std::wstring_view::npos ? std::wstring() : std::wstring(commandLine.substr(start));
}

namespace {

// --- режим отладки пакета (#59) ----------------------------------------------------------------

// Пакеты, для которых AppRoute включил режим отладки: запись — до включения, удаление — после
// снятия. Остаток после сбоя снимает RestorePackageDebugging.
constexpr wchar_t kDebugMarkerKey[] = L"Software\\AppRoute\\PackageDebugging";

void SetDebugMarker(const std::wstring& fullName, bool set)
{
    HKEY key = nullptr;
    if (set) {
        if (RegCreateKeyExW(HKEY_CURRENT_USER, kDebugMarkerKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key,
                            nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(key, fullName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(L""), sizeof(wchar_t));
            RegCloseKey(key);
        }
        return;
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDebugMarkerKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, fullName.c_str());
        RegCloseKey(key);
    }
}

HRESULT SetPackageDebugging(const std::wstring& fullName, const std::wstring* debugger, const wchar_t* environment)
{
    ComScope com;
    ComPtr<IPackageDebugSettings> settings;
    HRESULT hr = CoCreateInstance(CLSID_PackageDebugSettings, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&settings));
    if (FAILED(hr)) {
        return hr;
    }
    if (!debugger) {
        return settings->DisableDebugging(fullName.c_str());
    }
    return settings->EnableDebugging(fullName.c_str(), debugger->c_str(), const_cast<PZZWSTR>(environment));
}

// Блок окружения "ИМЯ=значение\0...\0\0" только из переменных правила с непустым значением
std::vector<wchar_t> RuleEnvironmentBlock(const EnvVars& vars)
{
    return MergeEnvironment(nullptr, true, vars);
}

std::wstring SignalName(const std::wstring& signal, bool ok)
{
    return std::format(L"Local\\AppRoute.PackageLaunch.{}.{}", signal, ok ? L"ok" : L"fail");
}

// Код результата помощника (DWORD) — общая память с тем же именем
std::wstring ResultName(const std::wstring& signal)
{
    return std::format(L"Local\\AppRoute.PackageLaunch.{}.rc", signal);
}

std::wstring NewSignal()
{
    GUID guid{};
    CoCreateGuid(&guid);
    std::wstring s = GuidToString(guid);
    std::erase_if(s, [](wchar_t c) { return c == L'{' || c == L'}'; });
    return s;
}

bool ProcessHasModule(DWORD pid, std::wstring_view moduleName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    for (BOOL more = Module32FirstW(snapshot, &entry); more && !found; more = Module32NextW(snapshot, &entry)) {
        found = EqualsIgnoreCase(entry.szModule, moduleName);
    }
    CloseHandle(snapshot);
    return found;
}

// Уже запущенные процессы пакета без hook-DLL: новое окно может открыться в них, мимо правила
bool PackageRunsWithoutRule(const std::wstring& fullName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    for (BOOL more = Process32FirstW(snapshot, &entry); more && !found; more = Process32NextW(snapshot, &entry)) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (!process) {
            continue;
        }
        if (EqualsIgnoreCase(ProcessPackageFullName(process), fullName) && ProcessUserMatchesCurrent(process)) {
            const bool is32 = IsProcessWow64(process);
            const std::wstring hook = HookDllPath(L"", is32);
            found = !ProcessHasModule(entry.th32ProcessID, hook);
        }
        CloseHandle(process);
    }
    CloseHandle(snapshot);
    return found;
}

LaunchResult LaunchPackage(const LaunchRequest& request, const EnvVars& vars, const std::wstring& binDir)
{
    LaunchResult result;
    const auto fail = [&](LaunchStatus status, DWORD error, std::wstring message) {
        result.status = status;
        result.error = error;
        result.message = std::move(message);
        return result;
    };
    RestorePackageDebugging();

    std::wstring error;
    const auto package = FindInstalledPackage(request.packageApp, &error);
    if (!package) {
        return fail(LaunchStatus::StartFailed, ERROR_NOT_FOUND, std::format(L"Ошибка запуска: {}", error));
    }
    result.image = package->executables.main;
    if (IsProtectedExecutable(result.image)) {
        return fail(LaunchStatus::Protected, ERROR_ACCESS_DENIED,
                    std::format(L"Отказ: {} — защитное или системное ПО, AppRoute в него не вмешивается.",
                                result.image));
    }
    // Отладчик — помощник своей разрядности; для процесса другой разрядности он сам вызовет второй
    constexpr bool self32 = sizeof(void*) == 4;
    const std::wstring helper = InjectHelperPath(binDir, self32);
    if (GetFileAttributesW(helper.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return fail(LaunchStatus::InjectFailed, ERROR_FILE_NOT_FOUND,
                    std::format(L"Не найден {} — он нужен для запуска приложений из пакетов", helper));
    }
    const bool runningWithoutRule = PackageRunsWithoutRule(package->fullName);

    const std::wstring signal = NewSignal();
    const HANDLE ok = CreateEventW(nullptr, TRUE, FALSE, SignalName(signal, true).c_str());
    const HANDLE failed = CreateEventW(nullptr, TRUE, FALSE, SignalName(signal, false).c_str());
    const HANDLE mapping =
        CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(DWORD), ResultName(signal).c_str());
    auto* helperCode = mapping ? static_cast<DWORD*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(DWORD)))
                               : nullptr;
    const auto release = [&] {
        if (helperCode) UnmapViewOfFile(helperCode);
        if (mapping) CloseHandle(mapping);
        if (ok) CloseHandle(ok);
        if (failed) CloseHandle(failed);
    };
    if (!ok || !failed || !helperCode) {
        const DWORD rc = GetLastError();
        release();
        return fail(LaunchStatus::StartFailed, rc, std::format(L"Ошибка запуска: {}", Win32ErrorMessage(rc)));
    }

    // Windows допишет к строке отладчика " -p <pid> -tid <tid>"
    const std::wstring debugger =
        std::format(L"\"{}\" --package-debug {} --signal {}", helper, package->fullName, signal);
    const std::vector<wchar_t> environment = RuleEnvironmentBlock(vars);
    SetDebugMarker(package->fullName, true);
    HRESULT hr = SetPackageDebugging(package->fullName, &debugger, environment.data());
    DWORD pid = 0;
    if (SUCCEEDED(hr)) {
        if (!LaunchPackagedApp(request.packageApp, request.packageArguments, &pid, &error)) {
            hr = E_FAIL;
        }
    } else {
        error = Win32ErrorMessage(static_cast<DWORD>(hr));
    }

    // Ждём результат помощника; процесс приложения может завершиться и сам (передал запуск
    // уже открытому экземпляру)
    DWORD wait = WAIT_FAILED;
    HANDLE process = pid ? OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) : nullptr;
    if (SUCCEEDED(hr)) {
        const HANDLE handles[] = {ok, failed};
        wait = WaitForMultipleObjects(2, handles, FALSE, 30000);
    }
    SetPackageDebugging(package->fullName, nullptr, nullptr);
    SetDebugMarker(package->fullName, false);
    const DWORD code = *helperCode;
    release();

    if (FAILED(hr)) {
        if (process) CloseHandle(process);
        return fail(LaunchStatus::StartFailed, static_cast<DWORD>(hr), std::format(L"Ошибка запуска: {}", error));
    }
    if (wait != WAIT_OBJECT_0) {
        if (process) CloseHandle(process);
        if (wait == WAIT_TIMEOUT) {
            return fail(LaunchStatus::InjectFailed, ERROR_TIMEOUT,
                        L"Правило к приложению из пакета не применено: помощник AppRoute не ответил.");
        }
        return fail(LaunchStatus::InjectFailed, code,
                    std::format(L"Правило к приложению из пакета не применено ({}-бит): {}",
                                result.is32Bit ? 32 : 64, Win32ErrorMessage(code)));
    }
    result.status = LaunchStatus::Started;
    result.pid = pid;
    result.process = process;
    result.is32Bit = process && IsProcessWow64(process);
    if (runningWithoutRule) {
        result.warning = L"Приложение уже было запущено без AppRoute — если окно открылось в нём, правило не "
                         L"действует: закройте приложение полностью и запустите снова через AppRoute.";
    }
    return result;
}

} // namespace

void RestorePackageDebugging()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kDebugMarkerKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return;
    }
    std::vector<std::wstring> names;
    wchar_t name[512];
    for (DWORD i = 0;; ++i) {
        DWORD length = static_cast<DWORD>(std::size(name));
        if (RegEnumValueW(key, i, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }
        names.emplace_back(name, length);
    }
    RegCloseKey(key);
    for (const auto& fullName : names) {
        SetPackageDebugging(fullName, nullptr, nullptr);
        SetDebugMarker(fullName, false);
    }
}

DWORD AttachPackageProcess(const std::wstring& packageFullName, const std::wstring& signal, DWORD pid, DWORD tid,
                           const std::wstring& binDir)
{
    const auto notify = [&](DWORD code) {
        const bool success = code == NO_ERROR;
        if (HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, ResultName(signal).c_str())) {
            if (auto* value = static_cast<DWORD*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(DWORD)))) {
                *value = code;
                UnmapViewOfFile(value);
            }
            CloseHandle(mapping);
        }
        if (HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, SignalName(signal, success).c_str())) {
            SetEvent(event);
            CloseHandle(event);
        }
    };
    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                                     PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                                 FALSE, pid);
    DWORD rc = NO_ERROR;
    if (!thread || !process) {
        rc = GetLastError();
    } else if (GetProcessIdOfThread(thread) != pid) {
        rc = ERROR_INVALID_PARAMETER;
    } else {
        // Только процесс этого пакета, своего пользователя, не защитное ПО — те же границы, что
        // при обычном запуске
        const std::wstring image = GetProcessImageName(process);
        if (!EqualsIgnoreCase(ProcessPackageFullName(process), packageFullName) || image.empty() ||
            IsProtectedExecutable(image) || IsAppRouteHelper(image) || !ProcessUserMatchesCurrent(process)) {
            rc = ERROR_ACCESS_DENIED;
        } else {
            rc = InjectRuleDll(process, binDir);
        }
    }
    if (rc == NO_ERROR) {
        ResumeThread(thread);
    } else if (rc == ERROR_ACCESS_DENIED || !process) {
        // Не наш процесс — не вмешиваемся: продолжает работу как обычно
        if (thread) {
            ResumeThread(thread);
        }
    } else {
        // Правило применить не удалось: как и при обычном запуске, без правила процесс не работает
        TerminateProcess(process, rc);
    }
    notify(rc);
    if (thread) CloseHandle(thread);
    if (process) CloseHandle(process);
    return rc;
}

std::wstring ResolveProgramPath(const std::wstring& commandLine)
{
    std::wstring token;
    if (!commandLine.empty() && commandLine.front() == L'"') {
        const auto end = commandLine.find(L'"', 1);
        token = commandLine.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
    } else {
        token = commandLine.substr(0, commandLine.find_first_of(L" \t"));
    }
    wchar_t full[MAX_PATH * 2] = {};
    const DWORD n = SearchPathW(nullptr, token.c_str(), L".exe", static_cast<DWORD>(std::size(full)), full, nullptr);
    if (n > 0 && n < std::size(full)) {
        return full;
    }
    return token;
}

LaunchResult LaunchWithRule(const LaunchRequest& request)
{
    const std::wstring binDir =
        request.binDir.empty() ? ModuleDirectory(reinterpret_cast<const void*>(&LaunchWithRule)) : request.binDir;
    const EnvVars vars = RuleEnvironment(request);
    if (!request.packageApp.empty()) {
        return LaunchPackage(request, vars, binDir);
    }

    LaunchResult result;
    // Правило — в окружении нового процесса; окружение текущего не трогаем
    std::vector<wchar_t> environment;
    if (wchar_t* own = GetEnvironmentStringsW()) {
        environment = MergeEnvironment(own, true, vars);
        FreeEnvironmentStringsW(own);
    } else {
        environment = MergeEnvironment(nullptr, true, vars);
    }

    std::wstring commandLine = request.commandLine;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (request.inheritStdHandles) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, request.inheritStdHandles,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment.data(), nullptr, &si, &pi)) {
        result.status = LaunchStatus::StartFailed;
        result.error = GetLastError();
        result.message = std::format(L"Ошибка запуска: {}", Win32ErrorMessage(result.error));
        return result;
    }

    result.image = GetProcessImageName(pi.hProcess);
    result.is32Bit = IsProcessWow64(pi.hProcess);
    const auto abort = [&](LaunchStatus status, DWORD error, std::wstring message) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        result.status = status;
        result.error = error;
        result.message = std::move(message);
        return result;
    };

    // Защитная граница: AppRoute не вмешивается в защитное ПО и системные процессы
    if (IsProtectedExecutable(result.image) || IsAppRouteHelper(result.image)) {
        return abort(LaunchStatus::Protected, ERROR_ACCESS_DENIED,
                     std::format(L"Отказ: {} — защитное или системное ПО, AppRoute в него не вмешивается.",
                                 result.image));
    }

    const DWORD rc = InjectRuleDll(pi.hProcess, binDir);
    if (rc != NO_ERROR) {
        std::wstring hint;
        if (rc == ERROR_MOD_NOT_FOUND || rc == ERROR_FILE_NOT_FOUND) {
            hint = std::format(L" (нужны {} и {} рядом с программой)",
                               HookDllPath(L"", result.is32Bit), InjectHelperPath(L"", result.is32Bit));
        }
        return abort(LaunchStatus::InjectFailed, rc,
                     std::format(L"Ошибка внедрения DLL ({}-бит): {}{}", result.is32Bit ? 32 : 64,
                                 Win32ErrorMessage(rc), hint));
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    result.status = LaunchStatus::Started;
    result.process = pi.hProcess;
    result.pid = pi.dwProcessId;
    return result;
}

LaunchRequest RequestForRule(const Rule& rule, std::wstring commandLine)
{
    LaunchRequest request;
    if (IsPackageApp(rule.app)) {
        request.packageApp = rule.app;
        request.packageArguments = ArgumentsAfterProgram(commandLine);
    }
    request.commandLine = std::move(commandLine);
    request.adapterGuid = rule.adapter;
    request.proxy = rule.proxy;
    request.includeChildren = rule.includeChildren;
    request.systemDns = rule.dns == DnsMode::System;
    request.policy.onUnavailable = rule.onUnavailable;
    request.policy.ipv6 = rule.ipv6;
    return request;
}

std::wstring CommandLineForApp(std::wstring_view app)
{
    std::wstring path(app);
    wchar_t expanded[MAX_PATH * 2] = {};
    const DWORD n = ExpandEnvironmentStringsW(path.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    if (n > 0 && n <= std::size(expanded)) {
        path = expanded;
    }
    return L"\"" + path + L"\"";
}

} // namespace approute
