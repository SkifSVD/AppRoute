// approute-run — запуск программы с привязкой её трафика к выбранному интерфейсу.
//
//   approute-run [--adapter <интерфейс>] [--config <файл>] [--log <файл>] [--no-wait] -- <программа> [аргументы...]
//
// Без --adapter правило для программы берётся из конфига (%APPDATA%\AppRoute\config.json, #11).
// Программа стартует приостановленной, в неё внедряется approute-hook64.dll, затем она
// продолжает работу. Правило передаётся через переменные окружения; дочерние процессы
// получают его от hook-DLL (#8). Полноценный launcher (x86) — issue #7.

#include "core/Config.h"
#include "core/NetAdapters.h"
#include "core/Policy.h"
#include "core/Process.h"
#include "core/Util.h"

#include <format>
#include <optional>
#include <string>
#include <string_view>

using namespace approute;

namespace {

void Out(std::wstring_view text)
{
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), len, nullptr, nullptr);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void Line(std::wstring_view text)
{
    Out(text);
    Out(L"\n");
}

void PrintUsage()
{
    Line(L"approute-run — запуск программы через выбранный сетевой интерфейс");
    Line(L"");
    Line(L"  approute-run [--adapter IF] [--config FILE] [--log FILE] [--on-unavailable block|default]");
    Line(L"               [--ipv6 follow|block|default] [--no-children] [--no-wait] -- PROGRAM [ARGS...]");
    Line(L"");
    Line(L"  IF             ifIndex, GUID или имя интерфейса (см. approute-routes list);");
    Line(L"                 без --adapter правило берётся из конфига (см. approute-config)");
    Line(L"  --config       файл конфига вместо %APPDATA%\\AppRoute\\config.json");
    Line(L"  --log          журнал hook-DLL (все процессы пишут в один файл)");
    Line(L"  --on-unavailable  если у интерфейса нет адреса (VPN отключён): block — блокировать");
    Line(L"                 соединения и DNS (по умолчанию), default — маршрутом по умолчанию");
    Line(L"  --ipv6         IPv6 без IPv6-адреса у интерфейса: follow (как --on-unavailable), block, default");
    Line(L"  --no-children  не применять правило к дочерним процессам");
    Line(L"  --no-wait      не ждать завершения программы");
}

struct Options {
    std::wstring adapter;
    std::wstring config;
    std::wstring log;
    bool wait = true;
    bool children = true;
    std::optional<OnUnavailable> onUnavailable;
    std::optional<Ipv6Mode> ipv6;
    std::wstring commandLine;   // всё после " -- ", как есть
};

// Командная строка программы берётся из исходной строки без перекодирования кавычек.
std::optional<std::wstring> TailAfterSeparator()
{
    const std::wstring_view cmd = GetCommandLineW();
    const auto pos = cmd.find(L" -- ");
    if (pos == std::wstring_view::npos) {
        return std::nullopt;
    }
    std::wstring tail(cmd.substr(pos + 4));
    while (!tail.empty() && tail.front() == L' ') {
        tail.erase(tail.begin());
    }
    if (tail.empty()) {
        return std::nullopt;
    }
    return tail;
}

std::optional<Options> ParseArgs(int argc, wchar_t** argv)
{
    Options o;
    int i = 1;
    for (; i < argc; ++i) {
        const std::wstring_view arg = argv[i];
        if (arg == L"--") {
            break;
        }
        if ((arg == L"--adapter" || arg == L"--log" || arg == L"--config") && i + 1 < argc) {
            (arg == L"--adapter" ? o.adapter : arg == L"--log" ? o.log : o.config) = argv[++i];
        } else if (arg == L"--on-unavailable" && i + 1 < argc) {
            const std::wstring_view v = argv[++i];
            if (v != L"block" && v != L"default") {
                Line(L"Ошибка: --on-unavailable block|default");
                return std::nullopt;
            }
            o.onUnavailable = v == L"default" ? OnUnavailable::Default : OnUnavailable::Block;
        } else if (arg == L"--ipv6" && i + 1 < argc) {
            const std::wstring_view v = argv[++i];
            if (v == L"follow") o.ipv6 = Ipv6Mode::Follow;
            else if (v == L"block") o.ipv6 = Ipv6Mode::Block;
            else if (v == L"default") o.ipv6 = Ipv6Mode::Default;
            else {
                Line(L"Ошибка: --ipv6 follow|block|default");
                return std::nullopt;
            }
        } else if (arg == L"--no-wait") {
            o.wait = false;
        } else if (arg == L"--no-children") {
            o.children = false;
        } else {
            Line(std::format(L"Ошибка: неизвестный параметр {}", arg));
            return std::nullopt;
        }
    }
    auto tail = TailAfterSeparator();
    if (i >= argc || !tail) {
        return std::nullopt;
    }
    o.commandLine = std::move(*tail);
    return o;
}

// Полный путь программы из командной строки — так же, как её найдёт CreateProcess
// (для поиска правила в конфиге до запуска: правило передаётся через окружение).
std::wstring ResolveProgram(const std::wstring& commandLine)
{
    std::wstring token;
    if (!commandLine.empty() && commandLine.front() == L'"') {
        const auto end = commandLine.find(L'"', 1);
        token = commandLine.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
    } else {
        token = commandLine.substr(0, commandLine.find_first_of(L" \t"));
    }
    wchar_t full[MAX_PATH * 2] = {};
    const DWORD n = SearchPathW(nullptr, token.c_str(), L".exe", static_cast<DWORD>(std::size(full)),
                                full, nullptr);
    if (n > 0 && n < std::size(full)) {
        return full;
    }
    return token;
}

std::wstring HookDllPath()
{
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring path = self;
    path.resize(path.find_last_of(L"\\/") + 1);
    return path + L"approute-hook64.dll";
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    auto options = ParseArgs(argc, argv);
    if (!options) {
        PrintUsage();
        return 1;
    }

    // Явный --adapter важнее конфига; без него ищем правило для программы
    std::optional<Rule> rule;
    if (options->adapter.empty()) {
        const std::wstring configPath = options->config.empty() ? DefaultConfigPath() : options->config;
        std::wstring error;
        const auto config = LoadConfig(configPath, &error);
        if (!config) {
            Line(std::format(L"Ошибка конфига: {}", error));
            return 1;
        }
        const std::wstring program = ResolveProgram(options->commandLine);
        const auto* found = FindRule(*config, program);
        if (!found) {
            Line(std::format(L"Ошибка: нет правила для «{}» в {} — укажите --adapter или добавьте",
                             program, configPath));
            Line(L"правило: approute-config add PROGRAM --adapter IF");
            return 1;
        }
        rule = *found;
        options->adapter = rule->adapter;
        if (!rule->includeChildren) {
            options->children = false;
        }
    }

    // Поведение без интерфейса: параметры командной строки важнее правила
    UnavailablePolicy policy;
    if (rule) {
        policy.onUnavailable = rule->onUnavailable;
        policy.ipv6 = rule->ipv6;
    }
    policy.onUnavailable = options->onUnavailable.value_or(policy.onUnavailable);
    policy.ipv6 = options->ipv6.value_or(policy.ipv6);

    // Интерфейс, заданный GUID, может быть сейчас отключён (VPN не подключён) — это не ошибка:
    // hook-DLL применит политику и подхватит интерфейс, когда он появится.
    const auto adapters = EnumerateAdapters();
    const auto* adapter = FindAdapter(adapters, options->adapter);
    std::wstring adapterGuid;
    std::wstring adapterLabel;
    if (adapter) {
        adapterGuid = GuidToString(adapter->guid);
        adapterLabel = adapter->alias;
    } else if (auto guid = NormalizeGuid(options->adapter)) {
        adapterGuid = *guid;
        adapterLabel = *guid;
        Line(std::format(L"Внимание: интерфейс {} сейчас отсутствует — {}.", *guid,
                         policy.UseDefaultRoute(false)
                             ? L"пока его нет, трафик пойдёт маршрутом по умолчанию (default)"
                             : L"пока его нет, соединения и DNS будут блокироваться (block)"));
    } else {
        Line(std::format(L"Ошибка: интерфейс «{}» не найден", options->adapter));
        return 1;
    }

    if (IsProcessElevated()) {
        Line(L"Внимание: запуск от имени администратора. Браузеры на Chromium в этом случае");
        Line(L"перезапускают себя без прав; AppRoute отслеживает это, но надёжнее обычный терминал.");
    }

    const auto dll = HookDllPath();
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Line(std::format(L"Ошибка: не найдена {}", dll));
        return 1;
    }

    // Прозрачность: явно сообщаем, что и куда направляется
    Line(std::format(L"AppRoute: трафик «{}»{} идёт через интерфейс «{}».",
                     options->commandLine,
                     options->children ? L" и его дочерних процессов" : L"",
                     adapterLabel));

    // Правило — через окружение: его унаследуют и дочерние процессы (issue #8)
    SetEnvironmentVariableW(kEnvAdapter, adapterGuid.c_str());
    SetEnvironmentVariableW(kEnvLog, options->log.empty() ? nullptr : options->log.c_str());
    SetEnvironmentVariableW(kEnvChildren, options->children ? nullptr : L"0");
    if (rule && rule->dns == DnsMode::System) {
        SetEnvironmentVariableW(kEnvDns, L"system");
    }
    SetEnvironmentVariableW(kEnvOnUnavailable, OnUnavailableEnvValue(policy.onUnavailable));
    SetEnvironmentVariableW(kEnvIpv6, Ipv6EnvValue(policy.ipv6));

    std::wstring commandLine = options->commandLine;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    // Как при обычном запуске из консоли: программа (в т.ч. GUI) получает наши stdin/stdout/stderr
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
        Line(std::format(L"Ошибка запуска: {}", Win32ErrorMessage(GetLastError())));
        return 1;
    }

    // Защитная граница: AppRoute не вмешивается в защитное ПО и системные процессы
    const std::wstring image = GetProcessImageName(pi.hProcess);
    if (IsProtectedExecutable(image)) {
        Line(std::format(L"Отказ: {} — защитное или системное ПО, AppRoute в него не вмешивается.",
                         image));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    if (IsProcessWow64(pi.hProcess)) {
        Line(L"Ошибка: 32-битные программы пока не поддерживаются (issue #7)");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    const DWORD rc = InjectDll(pi.hProcess, dll);
    if (rc != NO_ERROR) {
        Line(std::format(L"Ошибка внедрения DLL: {}", Win32ErrorMessage(rc)));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    DWORD exitCode = 0;
    if (options->wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }
    CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
}
