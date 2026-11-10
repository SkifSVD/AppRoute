#include "core/Launcher.h"

#include "core/Process.h"
#include "core/Util.h"

#include <format>
#include <vector>

namespace approute {

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
    LaunchResult result;
    const std::wstring binDir =
        request.binDir.empty() ? ModuleDirectory(reinterpret_cast<const void*>(&LaunchWithRule)) : request.binDir;

    // Правило — в окружении нового процесса; окружение текущего не трогаем
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
