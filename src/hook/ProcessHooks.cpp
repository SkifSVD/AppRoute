#include "ProcessHooks.h"
#include "Log.h"

#include "core/Process.h"
#include "core/Util.h"

#include <MinHook.h>

#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace approute::hook {

namespace {

// Недокументированная, но стабильная с Windows 7 функция kernelbase, в которую сходятся
// все CreateProcess*. Последний параметр — выходной токен (для внутренних нужд, обычно NULL).
using CreateProcessInternalW_t = BOOL(WINAPI*)(
    HANDLE token, LPCWSTR applicationName, LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles, DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation, PHANDLE newToken);

CreateProcessInternalW_t Real_CreateProcessInternalW = nullptr;
decltype(&::ResumeThread) Real_ResumeThread = &::ResumeThread;
decltype(&::CreateProcessWithTokenW) Real_CreateProcessWithTokenW = &::CreateProcessWithTokenW;
decltype(&::CreateProcessWithLogonW) Real_CreateProcessWithLogonW = &::CreateProcessWithLogonW;

RuleConfig g_config;
std::wstring g_dllPath;

// Дети, которых родитель сам создал приостановленными (песочница Chromium, другие инжекторы):
// родитель ещё готовит процесс, поэтому внедряемся только в момент его ResumeThread.
// Ключ — id главного потока ребёнка.
struct PendingChild {
    HANDLE process = nullptr;   // свой дубликат описателя
    DWORD pid = 0;
    std::wstring name;
};
SRWLOCK g_pendingLock = SRWLOCK_INIT;
std::unordered_map<DWORD, PendingChild> g_pending;

std::wstring OwnModulePath()
{
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&OwnModulePath), &self);
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(self, path, MAX_PATH);
    return path;
}

std::wstring ShortName(LPCWSTR applicationName, LPCWSTR commandLine)
{
    // Командная строка информативнее (у Chromium в ней --type=...), имя файла — запасной вариант
    std::wstring s = commandLine ? commandLine : (applicationName ? applicationName : L"?");
    auto option = [&](const wchar_t* name) -> std::wstring {
        const auto pos = s.find(name);
        if (pos == std::wstring::npos) {
            return {};
        }
        const auto end = s.find(L' ', pos);
        return s.substr(pos, end == std::wstring::npos ? std::wstring::npos : end - pos);
    };
    if (auto type = option(L"--type="); !type.empty()) {
        if (auto sub = option(L"--utility-sub-type="); !sub.empty()) {
            type += L" " + sub;
        }
        s = std::move(type);
    }
    if (s.size() > 160) {
        s.resize(160);
        s += L"…";
    }
    return s;
}

// Дочерние процессы Chromium/Electron (--type=...) в сеть ходят только через сетевой сервис;
// остальные (renderer, gpu, storage и т.д.) работают в песочнице, сеть не используют, а часть
// из них падает от сторонней DLL (storage.mojom.StorageService) — их не трогаем.
bool ShouldInject(LPCWSTR commandLine)
{
    if (!commandLine) {
        return true;
    }
    const std::wstring_view cmd = commandLine;
    if (cmd.find(L" --type=") == std::wstring_view::npos) {
        return true;
    }
    return cmd.find(L"--utility-sub-type=network.mojom.NetworkService") != std::wstring_view::npos;
}

void InjectChild(HANDLE process, DWORD pid, const std::wstring& name)
{
    // Защитные границы: не внедряемся в защитное ПО / системные процессы и в процессы
    // другого пользователя, даже если они оказались потомками (например, через оболочку).
    const std::wstring image = GetProcessImageName(process);
    if (IsProtectedExecutable(image.empty() ? name : image)) {
        Log(L"дочерний процесс %lu пропущен (защищённый/системный): %ls", pid,
            (image.empty() ? name : image).c_str());
        return;
    }
    if (!ProcessUserMatchesCurrent(process)) {
        Log(L"дочерний процесс %lu пропущен (другой пользователь): %ls", pid, name.c_str());
        return;
    }
    if (IsProcessWow64(process)) {
        Log(L"дочерний процесс %lu (32-бит) без правила — не поддерживается (#7): %ls", pid, name.c_str());
        return;
    }
    const DWORD rc = InjectDll(process, g_dllPath, 10000);
    if (rc == NO_ERROR) {
        Log(L"дочерний процесс %lu: правило применено: %ls", pid, name.c_str());
    } else {
        Log(L"дочерний процесс %lu: внедрение не удалось (%ls): %ls", pid, Win32ErrorMessage(rc).c_str(), name.c_str());
    }
}

std::vector<wchar_t> RuleEnvironment(const void* environment, bool unicode)
{
    EnvVars vars = {{kEnvAdapter, g_config.adapterGuid}};
    if (!g_config.logPath.empty()) {
        vars.emplace_back(kEnvLog, g_config.logPath);
    }
    return MergeEnvironment(environment, unicode, vars);
}

// Ребёнок создан приостановленным. Если родитель сам не просил приостановки — внедряемся и
// запускаем; иначе родитель ещё готовит процесс — внедримся при его ResumeThread.
void AfterCreated(const PROCESS_INFORMATION& pi, bool callerWantsSuspended, std::wstring name)
{
    if (!callerWantsSuspended) {
        InjectChild(pi.hProcess, pi.dwProcessId, name);
        Real_ResumeThread(pi.hThread);
    } else {
        PendingChild pending;
        pending.pid = pi.dwProcessId;
        pending.name = std::move(name);
        if (DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(),
                            &pending.process, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            AcquireSRWLockExclusive(&g_pendingLock);
            g_pending[pi.dwThreadId] = std::move(pending);
            ReleaseSRWLockExclusive(&g_pendingLock);
        }
    }
    SetLastError(NO_ERROR);
}

BOOL WINAPI Hook_CreateProcessInternalW(
    HANDLE token, LPCWSTR applicationName, LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles, DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation, PHANDLE newToken)
{
    if (!processInformation || !ShouldInject(commandLine)) {
        return Real_CreateProcessInternalW(token, applicationName, commandLine, processAttributes,
            threadAttributes, inheritHandles, creationFlags, environment, currentDirectory,
            startupInfo, processInformation, newToken);
    }

    // Явно переданное окружение может не содержать правила (браузеры собирают его сами)
    std::vector<wchar_t> mergedEnvironment;
    if (environment) {
        mergedEnvironment = RuleEnvironment(environment, (creationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        environment = mergedEnvironment.data();
        creationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    const bool callerWantsSuspended = (creationFlags & CREATE_SUSPENDED) != 0;
    if (!Real_CreateProcessInternalW(token, applicationName, commandLine, processAttributes,
            threadAttributes, inheritHandles, creationFlags | CREATE_SUSPENDED, environment,
            currentDirectory, startupInfo, processInformation, newToken)) {
        return FALSE;
    }
    AfterCreated(*processInformation, callerWantsSuspended, ShortName(applicationName, commandLine));
    return TRUE;
}

// CreateProcessWithTokenW / CreateProcessWithLogonW: процесс создаёт служба seclogon, а не мы,
// поэтому CreateProcessInternalW их не видит. Так браузеры на Chromium перезапускают себя без
// прав администратора. Без явного окружения seclogon берёт окружение профиля пользователя —
// правила там нет, поэтому окружение передаём всегда.
template <typename CreateFn>
BOOL CreateViaSeclogon(LPCWSTR applicationName, LPWSTR commandLine, DWORD creationFlags, LPVOID environment,
                       LPPROCESS_INFORMATION processInformation, CreateFn create)
{
    if (!processInformation || !ShouldInject(commandLine)) {
        return create(creationFlags, environment);
    }

    std::vector<wchar_t> mergedEnvironment;
    if (environment) {
        mergedEnvironment = RuleEnvironment(environment, (creationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
    } else if (wchar_t* own = GetEnvironmentStringsW()) {
        mergedEnvironment = RuleEnvironment(own, true);
        FreeEnvironmentStringsW(own);
    }
    if (!mergedEnvironment.empty()) {
        environment = mergedEnvironment.data();
        creationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    const bool callerWantsSuspended = (creationFlags & CREATE_SUSPENDED) != 0;
    if (!create(creationFlags | CREATE_SUSPENDED, environment)) {
        return FALSE;
    }
    AfterCreated(*processInformation, callerWantsSuspended, ShortName(applicationName, commandLine));
    return TRUE;
}

BOOL WINAPI Hook_CreateProcessWithTokenW(HANDLE token, DWORD logonFlags, LPCWSTR applicationName,
    LPWSTR commandLine, DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
    LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation)
{
    return CreateViaSeclogon(applicationName, commandLine, creationFlags, environment, processInformation,
        [&](DWORD flags, LPVOID env) {
            return Real_CreateProcessWithTokenW(token, logonFlags, applicationName, commandLine, flags, env,
                                                currentDirectory, startupInfo, processInformation);
        });
}

BOOL WINAPI Hook_CreateProcessWithLogonW(LPCWSTR username, LPCWSTR domain, LPCWSTR password, DWORD logonFlags,
    LPCWSTR applicationName, LPWSTR commandLine, DWORD creationFlags, LPVOID environment,
    LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation)
{
    return CreateViaSeclogon(applicationName, commandLine, creationFlags, environment, processInformation,
        [&](DWORD flags, LPVOID env) {
            return Real_CreateProcessWithLogonW(username, domain, password, logonFlags, applicationName,
                                                commandLine, flags, env, currentDirectory, startupInfo,
                                                processInformation);
        });
}

DWORD WINAPI Hook_ResumeThread(HANDLE thread)
{
    const DWORD tid = GetThreadId(thread);
    PendingChild pending;
    bool found = false;
    if (tid != 0) {
        AcquireSRWLockExclusive(&g_pendingLock);
        if (auto it = g_pending.find(tid); it != g_pending.end()) {
            pending = std::move(it->second);
            g_pending.erase(it);
            found = true;
        }
        ReleaseSRWLockExclusive(&g_pendingLock);
    }
    if (found) {
        InjectChild(pending.process, pending.pid, pending.name);
        CloseHandle(pending.process);
    }
    return Real_ResumeThread(thread);
}

} // namespace

void CreateProcessHooks(const RuleConfig& config)
{
    g_config = config;
    if (!g_config.includeChildren) {
        Log(L"дочерние процессы: правило не распространяется (%ls=0)", kEnvChildren);
        return;
    }
    g_dllPath = OwnModulePath();

    const MH_STATUS st = MH_CreateHookApi(L"kernelbase", "CreateProcessInternalW",
        reinterpret_cast<LPVOID>(&Hook_CreateProcessInternalW),
        reinterpret_cast<LPVOID*>(&Real_CreateProcessInternalW));
    if (st != MH_OK) {
        Log(L"не удалось перехватить CreateProcessInternalW: %hs — дочерние процессы без правила",
            MH_StatusToString(st));
        return;
    }
    const MH_STATUS rs = MH_CreateHookApi(L"kernelbase", "ResumeThread",
        reinterpret_cast<LPVOID>(&Hook_ResumeThread), reinterpret_cast<LPVOID*>(&Real_ResumeThread));
    if (rs != MH_OK) {
        Log(L"не удалось перехватить ResumeThread: %hs", MH_StatusToString(rs));
    }
    for (const auto& [name, detour, original] : {
             std::tuple{"CreateProcessWithTokenW", reinterpret_cast<LPVOID>(&Hook_CreateProcessWithTokenW),
                        reinterpret_cast<LPVOID*>(&Real_CreateProcessWithTokenW)},
             std::tuple{"CreateProcessWithLogonW", reinterpret_cast<LPVOID>(&Hook_CreateProcessWithLogonW),
                        reinterpret_cast<LPVOID*>(&Real_CreateProcessWithLogonW)}}) {
        if (const MH_STATUS s = MH_CreateHookApi(L"advapi32", name, detour, original); s != MH_OK) {
            Log(L"не удалось перехватить %hs: %hs", name, MH_StatusToString(s));
        }
    }
}

} // namespace approute::hook
