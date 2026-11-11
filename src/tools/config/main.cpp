// approute-config — правила AppRoute в конфиге (%APPDATA%\AppRoute\config.json, issue #11).
//
//   approute-config [--config FILE] path | show | check
//   approute-config [--config FILE] add PROGRAM --adapter IF | --proxy ADDR [--on-unavailable block|default]
//                   [--dns adapter|system] [--ipv6 follow|block|default] [--no-children] [--autostart]
//   approute-config [--config FILE] remove PROGRAM
//   approute-config [--config FILE] autostart PROGRAM on|off
//   approute-config packages
//   approute-config proxy-auth ADDR USER | ADDR --remove

#include "core/Autostart.h"
#include "core/Config.h"
#include "core/NetAdapters.h"
#include "core/Process.h"
#include "core/PackagedApps.h"
#include "core/ProxyCredentials.h"
#include "core/Socks5.h"
#include "core/Util.h"

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace approute;

namespace {

void Out(std::wstring_view text)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    const std::string utf8 = ToUtf8(text);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void Line(std::wstring_view text)
{
    Out(text);
    Out(L"\n");
}

void PrintUsage()
{
    Line(L"approute-config — правила маршрутизации приложений");
    Line(L"");
    Line(L"  approute-config [--config FILE] path              путь к файлу конфига");
    Line(L"  approute-config [--config FILE] show              список правил");
    Line(L"  approute-config [--config FILE] check             проверить конфиг");
    Line(L"  approute-config [--config FILE] add PROGRAM --adapter IF | --proxy ADDR [параметры]");
    Line(L"  approute-config [--config FILE] remove PROGRAM");
    Line(L"  approute-config [--config FILE] autostart PROGRAM on|off  запускать при входе в Windows");
    Line(L"  approute-config packages                          приложения из Microsoft Store и MSIX");
    Line(L"  approute-config proxy-auth ADDR USER              логин и пароль SOCKS5-прокси (пароль");
    Line(L"                                                    спрашивается; хранится в диспетчере");
    Line(L"                                                    учётных данных Windows, не в конфиге)");
    Line(L"  approute-config proxy-auth ADDR --remove          удалить логин и пароль прокси");
    Line(L"");
    Line(L"  PROGRAM            путь к программе, только имя файла (подходит в любом каталоге) или");
    Line(L"                     приложение из пакета: Семейство!Id, см. packages");
    Line(L"  --adapter IF       ifIndex, GUID или имя интерфейса; в конфиг пишется GUID");
    Line(L"  --proxy ADDR       вместо интерфейса — SOCKS5-прокси, например 127.0.0.1:10808");
    Line(L"  --on-unavailable   block (по умолчанию) | default — если интерфейс отключён");
    Line(L"  --dns              adapter (по умолчанию) | system");
    Line(L"  --ipv6             follow (по умолчанию) | block | default");
    Line(L"  --no-children      не применять правило к дочерним процессам");
    Line(L"  --autostart        запускать программу при входе в Windows через AppRoute (нужен полный");
    Line(L"                     путь; AppRoute добавляет одну запись автозагрузки для себя)");
}

int SyncAutostartEntry(const Config& config, const std::wstring& path);

const wchar_t* Name(OnUnavailable v) { return v == OnUnavailable::Block ? L"block" : L"default"; }
const wchar_t* Name(DnsMode v) { return v == DnsMode::Adapter ? L"adapter" : L"system"; }
const wchar_t* Name(Ipv6Mode v)
{
    return v == Ipv6Mode::Follow ? L"follow" : v == Ipv6Mode::Block ? L"block" : L"default";
}

// Путь программы для правила: имя файла оставляем как есть, путь — полным.
std::wstring RuleApp(const std::wstring& program)
{
    if (program.find_first_of(L"\\/") == std::wstring::npos) {
        return program;
    }
    wchar_t full[MAX_PATH * 2] = {};
    const DWORD n = GetFullPathNameW(program.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
    return n > 0 && n < std::size(full) ? std::wstring(full) : program;
}

int Show(const Config& config)
{
    const auto adapters = EnumerateAdapters();
    const auto adapterLabel = [&](const std::wstring& guid) {
        const auto* a = FindAdapter(adapters, guid);
        if (a) {
            return std::format(L"{} {}", a->alias, guid);
        }
        const auto* known = FindKnownAdapter(config, guid);
        return std::format(L"{}<нет в системе> {}", known ? known->name + L" " : L"", guid);
    };
    Line(std::format(L"Основной интерфейс: {}",
                     config.primary == L"auto" ? std::wstring(L"auto") : adapterLabel(config.primary)));
    if (config.rules.empty()) {
        Line(L"Правил нет. Добавить: approute-config add PROGRAM --adapter IF");
        return 0;
    }
    for (const auto& rule : config.rules) {
        Line(IsPackageApp(rule.app) ? std::format(L"{} ({}, из пакета)", rule.app, PackagedAppName(rule.app))
                                    : rule.app);
        Line(std::format(L"    → {}", rule.proxy.empty() ? adapterLabel(rule.adapter) : L"SOCKS5-прокси " + rule.proxy));
        if (!rule.proxy.empty()) {
            const auto address = ParseProxyAddress(rule.proxy);
            const auto credential = address ? ReadProxyCredential(*address) : std::nullopt;
            Line(credential ? std::format(L"    логин {}, пароль задан", credential->user)
                            : std::wstring(L"    без логина и пароля"));
        }
        Line(std::format(L"    onUnavailable={} dns={} ipv6={} includeChildren={}{}", Name(rule.onUnavailable),
                         Name(rule.dns), Name(rule.ipv6), rule.includeChildren ? L"true" : L"false",
                         rule.autostart ? L" autostart=true" : L""));
    }
    if (const auto entry = ReadAutostartEntry()) {
        Line(L"Запуск при входе в Windows: " + *entry);
    }
    return 0;
}

int Add(Config& config, const std::wstring& path, const std::vector<std::wstring>& args)
{
    if (args.empty()) {
        PrintUsage();
        return 1;
    }
    Rule rule;
    rule.app = RuleApp(args[0]);
    std::wstring adapterArg;
    std::wstring proxyArg;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::wstring& arg = args[i];
        const bool hasValue = i + 1 < args.size();
        if (arg == L"--adapter" && hasValue) {
            adapterArg = args[++i];
        } else if (arg == L"--proxy" && hasValue) {
            proxyArg = args[++i];
        } else if (arg == L"--on-unavailable" && hasValue) {
            const auto& v = args[++i];
            if (v == L"block") rule.onUnavailable = OnUnavailable::Block;
            else if (v == L"default") rule.onUnavailable = OnUnavailable::Default;
            else { Line(L"Ошибка: --on-unavailable block|default"); return 1; }
        } else if (arg == L"--dns" && hasValue) {
            const auto& v = args[++i];
            if (v == L"adapter") rule.dns = DnsMode::Adapter;
            else if (v == L"system") rule.dns = DnsMode::System;
            else { Line(L"Ошибка: --dns adapter|system"); return 1; }
        } else if (arg == L"--ipv6" && hasValue) {
            const auto& v = args[++i];
            if (v == L"follow") rule.ipv6 = Ipv6Mode::Follow;
            else if (v == L"block") rule.ipv6 = Ipv6Mode::Block;
            else if (v == L"default") rule.ipv6 = Ipv6Mode::Default;
            else { Line(L"Ошибка: --ipv6 follow|block|default"); return 1; }
        } else if (arg == L"--no-children") {
            rule.includeChildren = false;
        } else if (arg == L"--autostart") {
            rule.autostart = true;
        } else {
            Line(std::format(L"Ошибка: неизвестный параметр {}", arg));
            return 1;
        }
    }
    if (adapterArg.empty() == proxyArg.empty()) {
        Line(L"Ошибка: укажите --adapter IF или --proxy ADDR");
        return 1;
    }
    std::wstring target;
    if (!proxyArg.empty()) {
        const auto address = ParseProxyAddress(proxyArg);
        if (!address) {
            Line(std::format(L"Ошибка: адрес прокси «{}» — нужен IP-адрес и порт, например 127.0.0.1:10808", proxyArg));
            return 1;
        }
        rule.proxy = FormatProxyAddress(*address);
        target = L"SOCKS5-прокси " + rule.proxy;
    } else {
        // Интерфейс должен существовать сейчас: так имя/ifIndex надёжно превращаются в GUID
        const auto adapters = EnumerateAdapters();
        const auto* adapter = FindAdapter(adapters, adapterArg);
        if (!adapter) {
            Line(std::format(L"Ошибка: интерфейс «{}» не найден (см. approute-routes list)", adapterArg));
            return 1;
        }
        rule.adapter = GuidToString(adapter->guid);
        RememberAdapter(config, {rule.adapter, adapter->alias, adapter->description});
        target = adapter->alias;
    }
    if (const auto problem = ValidateRule(rule)) {
        Line(L"Ошибка: " + *problem);
        return 1;
    }

    bool replaced = false;
    for (auto& existing : config.rules) {
        if (EqualsIgnoreCase(existing.app, rule.app)) {
            existing = rule;
            replaced = true;
        }
    }
    if (!replaced) {
        config.rules.push_back(rule);
    }
    std::wstring error;
    if (!SaveConfig(path, config, &error)) {
        Line(std::format(L"Ошибка записи: {}", error));
        return 1;
    }
    Line(std::format(L"{}: {} → {}", replaced ? L"Правило обновлено" : L"Правило добавлено", rule.app, target));
    return SyncAutostartEntry(config, path);
}

// Запись автозапуска AppRoute (#60) — по флажкам правил; окно approute-gui.exe — рядом
int SyncAutostartEntry(const Config& config, const std::wstring& path)
{
    const std::wstring gui = ModuleDirectory(reinterpret_cast<const void*>(&SyncAutostartEntry)) + L"approute-gui.exe";
    if (AutostartWanted(config) && GetFileAttributesW(gui.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Line(std::format(L"Ошибка: для запуска при входе нужен {}", gui));
        return 1;
    }
    std::wstring error;
    if (!SyncAutostart(config, gui, path, &error)) {
        Line(L"Ошибка: " + error);
        return 1;
    }
    return 0;
}

int Autostart(Config& config, const std::wstring& path, const std::vector<std::wstring>& args)
{
    if (args.size() != 2 || (args[1] != L"on" && args[1] != L"off")) {
        PrintUsage();
        return 1;
    }
    const std::wstring app = RuleApp(args[0]);
    Rule* rule = nullptr;
    for (auto& r : config.rules) {
        if (EqualsIgnoreCase(r.app, app)) {
            rule = &r;
        }
    }
    if (!rule) {
        Line(std::format(L"Ошибка: правила для «{}» нет", app));
        return 1;
    }
    Rule changed = *rule;
    changed.autostart = args[1] == L"on";
    if (const auto problem = ValidateRule(changed)) {
        Line(L"Ошибка: " + *problem);
        return 1;
    }
    *rule = changed;
    std::wstring error;
    if (!SaveConfig(path, config, &error)) {
        Line(std::format(L"Ошибка записи: {}", error));
        return 1;
    }
    Line(std::format(L"{}: {}", changed.autostart ? L"Запуск при входе в Windows включён" : L"Запуск при входе выключен",
                     changed.app));
    if (changed.autostart) {
        for (const auto& own : FindOwnAutostart(changed)) {
            Line(std::format(L"Внимание: у программы есть своя автозагрузка {} — она запустит программу мимо "
                             L"AppRoute; отключите её в «Параметры → Приложения → Автозагрузка».",
                             own));
        }
    }
    return SyncAutostartEntry(config, path);
}

int Packages()
{
    const auto apps = EnumeratePackagedApps();
    if (apps.empty()) {
        Line(L"Приложений полного доверия из пакетов не найдено.");
        return 0;
    }
    for (const auto& a : apps) {
        Line(a.name);
        Line(std::format(L"    {}", a.app));
        Line(std::format(L"    {}", a.executable));
    }
    Line(L"");
    Line(L"Правило: approute-config add Семейство!Id --adapter IF | --proxy ADDR (запуск через AppRoute;");
    Line(L"с драйвером WFP — при любом запуске).");
    return 0;
}

// Пароль с консоли без отображения; если ввод перенаправлен — первая строка stdin
std::optional<std::wstring> ReadPassword()
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(in, &mode)) {
        Out(L"Пароль: ");
        SetConsoleMode(in, (mode & ~ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        std::wstring buffer(1024, L'\0');
        DWORD read = 0;
        const BOOL ok = ReadConsoleW(in, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr);
        SetConsoleMode(in, mode);
        Line(L"");
        if (!ok) {
            return std::nullopt;
        }
        buffer.resize(read);
        while (!buffer.empty() && (buffer.back() == L'\n' || buffer.back() == L'\r')) {
            buffer.pop_back();
        }
        return buffer;
    }
    std::string bytes;
    char c = 0;
    DWORD n = 0;
    while (ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') {
        bytes.push_back(c);
    }
    if (!bytes.empty() && bytes.back() == '\r') {
        bytes.pop_back();
    }
    auto text = FromUtf8(bytes);
    SecureZeroMemory(bytes.data(), bytes.size());
    return text;
}

int ProxyAuth(const std::vector<std::wstring>& args)
{
    if (args.size() != 2) {
        PrintUsage();
        return 1;
    }
    const auto address = ParseProxyAddress(args[0]);
    if (!address) {
        Line(std::format(L"Ошибка: адрес прокси «{}» — нужен IP-адрес и порт, например 127.0.0.1:10808", args[0]));
        return 1;
    }
    if (args[1] == L"--remove") {
        Line(DeleteProxyCredential(*address)
                 ? std::format(L"Логин и пароль прокси {} удалены", FormatProxyAddress(*address))
                 : std::format(L"Для прокси {} логин и пароль не заданы", FormatProxyAddress(*address)));
        return 0;
    }
    ProxyCredential credential;
    credential.user = args[1];
    auto password = ReadPassword();
    if (!password) {
        Line(L"Ошибка: пароль не прочитан");
        return 1;
    }
    credential.password = std::move(*password);
    std::wstring error;
    if (!SaveProxyCredential(*address, credential, &error)) {
        Line(L"Ошибка: " + error);
        return 1;
    }
    Line(std::format(L"Логин и пароль прокси {} сохранены в диспетчере учётных данных Windows ({})",
                     FormatProxyAddress(*address), ProxyCredentialTarget(*address)));
    const Socks5Auth check = CheckProxy(*address, &credential, 2000);
    if (check != Socks5Auth::NoAnswer) {
        Line(std::format(L"Проверка: {}", Socks5AuthText(check)));
    }
    return 0;
}

int Remove(Config& config, const std::wstring& path, const std::vector<std::wstring>& args)
{
    if (args.size() != 1) {
        PrintUsage();
        return 1;
    }
    const std::wstring app = RuleApp(args[0]);
    const auto before = config.rules.size();
    std::erase_if(config.rules, [&](const Rule& r) { return EqualsIgnoreCase(r.app, app); });
    if (config.rules.size() == before) {
        Line(std::format(L"Правила для «{}» нет", app));
        return 1;
    }
    std::wstring error;
    if (!SaveConfig(path, config, &error)) {
        Line(std::format(L"Ошибка записи: {}", error));
        return 1;
    }
    Line(std::format(L"Правило удалено: {}", app));
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::wstring> args(argv + 1, argv + argc);
    std::wstring path = DefaultConfigPath();
    if (args.size() >= 2 && args[0] == L"--config") {
        path = args[1];
        args.erase(args.begin(), args.begin() + 2);
    }
    if (args.empty()) {
        PrintUsage();
        return 1;
    }
    const std::wstring command = args[0];
    args.erase(args.begin());

    if (command == L"path") {
        Line(path);
        return 0;
    }
    if (command == L"packages") {
        return Packages();
    }
    if (command == L"proxy-auth") {
        return ProxyAuth(args);
    }

    std::wstring error;
    auto config = LoadConfig(path, &error);
    if (!config) {
        Line(std::format(L"Ошибка конфига: {}", error));
        return 1;
    }

    if (command == L"show") {
        return Show(*config);
    }
    if (command == L"check") {
        Line(std::format(L"Конфиг в порядке: {} (правил: {})", path, config->rules.size()));
        return 0;
    }
    if (command == L"add") {
        return Add(*config, path, args);
    }
    if (command == L"remove") {
        const int rc = Remove(*config, path, args);
        return rc ? rc : SyncAutostartEntry(*config, path);
    }
    if (command == L"autostart") {
        return Autostart(*config, path, args);
    }
    PrintUsage();
    return 1;
}
