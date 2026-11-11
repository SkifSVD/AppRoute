// approute-run — запуск программы с привязкой её трафика к выбранному интерфейсу.
//
//   approute-run [--adapter <интерфейс> | --proxy <адрес>] [--config <файл>] [--log <файл>] [--no-wait] -- <программа> [аргументы...]
//
// Без --adapter правило для программы берётся из конфига (%APPDATA%\AppRoute\config.json, #11).
// Программа стартует приостановленной, в неё внедряется approute-hook64.dll, затем она
// продолжает работу. Правило передаётся через переменные окружения; дочерние процессы
// получают его от hook-DLL (#8). 32-битные программы — через approute-inject32.exe (#7).

#include "core/Config.h"
#include "core/Launcher.h"
#include "core/NetAdapters.h"
#include "core/Socks5.h"
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
    Line(L"  approute-run [--adapter IF | --proxy ADDR] [--config FILE] [--log FILE] [--on-unavailable block|default]");
    Line(L"               [--ipv6 follow|block|default] [--no-children] [--no-wait] -- PROGRAM [ARGS...]");
    Line(L"");
    Line(L"  IF             ifIndex, GUID или имя интерфейса (см. approute-routes list);");
    Line(L"                 без --adapter правило берётся из конфига (см. approute-config)");
    Line(L"  --proxy        вместо интерфейса — SOCKS5-прокси, например 127.0.0.1:10808: TCP идёт через");
    Line(L"                 него, имена разрешает прокси, UDP — через UDP ASSOCIATE (локальные адреса — напрямую)");
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
    std::wstring proxy;
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
        if ((arg == L"--adapter" || arg == L"--log" || arg == L"--config" || arg == L"--proxy") && i + 1 < argc) {
            (arg == L"--adapter" ? o.adapter : arg == L"--log" ? o.log : arg == L"--proxy" ? o.proxy : o.config) = argv[++i];
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
    if (options->adapter.empty() && options->proxy.empty()) {
        const std::wstring configPath = options->config.empty() ? DefaultConfigPath() : options->config;
        std::wstring error;
        const auto config = LoadConfig(configPath, &error);
        if (!config) {
            Line(std::format(L"Ошибка конфига: {}", error));
            return 1;
        }
        const std::wstring program = ResolveProgramPath(options->commandLine);
        const auto* found = FindRule(*config, program);
        if (!found) {
            Line(std::format(L"Ошибка: нет правила для «{}» в {} — укажите --adapter или добавьте",
                             program, configPath));
            Line(L"правило: approute-config add PROGRAM --adapter IF");
            return 1;
        }
        rule = *found;
        options->adapter = rule->adapter;
        options->proxy = rule->proxy;
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

    if (!options->proxy.empty()) {
        // Правило «прокси» (#17)
        const auto address = ParseProxyAddress(options->proxy);
        if (!address) {
            Line(std::format(L"Ошибка: адрес прокси «{}» — нужен IP-адрес и порт, например 127.0.0.1:10808",
                             options->proxy));
            return 1;
        }
        Line(std::format(L"AppRoute: трафик «{}»{} (TCP и UDP) идёт через SOCKS5-прокси {}; имена разрешает "
                         L"прокси.",
                         options->commandLine, options->children ? L" и его дочерних процессов" : L"",
                         FormatProxyAddress(*address)));
        LaunchRequest request = rule ? RequestForRule(*rule, options->commandLine) : LaunchRequest{};
        request.commandLine = options->commandLine;
        request.adapterGuid.clear();
        request.proxy = FormatProxyAddress(*address);
        request.logPath = options->log;
        request.includeChildren = options->children;
        request.policy = policy;
        auto launched = LaunchWithRule(request);
        if (!launched.Ok()) {
            Line(launched.message);
            return 1;
        }
        DWORD exitCode = 0;
        if (options->wait) {
            WaitForSingleObject(launched.process, INFINITE);
            GetExitCodeProcess(launched.process, &exitCode);
        }
        CloseHandle(launched.process);
        return static_cast<int>(exitCode);
    }

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

    // Прозрачность: явно сообщаем, что и куда направляется
    Line(std::format(L"AppRoute: трафик «{}»{} идёт через интерфейс «{}».",
                     options->commandLine,
                     options->children ? L" и его дочерних процессов" : L"",
                     adapterLabel));

    LaunchRequest request = rule ? RequestForRule(*rule, options->commandLine) : LaunchRequest{};
    request.commandLine = options->commandLine;
    request.adapterGuid = adapterGuid;
    request.logPath = options->log;
    request.includeChildren = options->children;
    request.policy = policy;
    auto launched = LaunchWithRule(request);
    if (!launched.Ok()) {
        Line(launched.message);
        return 1;
    }
    if (launched.is32Bit) {
        Line(L"(32-битная программа)");
    }

    DWORD exitCode = 0;
    if (options->wait) {
        WaitForSingleObject(launched.process, INFINITE);
        GetExitCodeProcess(launched.process, &exitCode);
    }
    CloseHandle(launched.process);
    return static_cast<int>(exitCode);
}
