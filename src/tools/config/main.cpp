// approute-config — правила AppRoute в конфиге (%APPDATA%\AppRoute\config.json, issue #11).
//
//   approute-config [--config FILE] path | show | check
//   approute-config [--config FILE] add PROGRAM --adapter IF [--on-unavailable block|default]
//                   [--dns adapter|system] [--ipv6 follow|block|default] [--no-children]
//   approute-config [--config FILE] remove PROGRAM

#include "core/Config.h"
#include "core/NetAdapters.h"
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
    Line(L"  approute-config [--config FILE] add PROGRAM --adapter IF [параметры]");
    Line(L"  approute-config [--config FILE] remove PROGRAM");
    Line(L"");
    Line(L"  PROGRAM            путь к программе или только имя файла (подходит в любом каталоге)");
    Line(L"  --adapter IF       ifIndex, GUID или имя интерфейса; в конфиг пишется GUID");
    Line(L"  --on-unavailable   block (по умолчанию) | default — если интерфейс отключён");
    Line(L"  --dns              adapter (по умолчанию) | system");
    Line(L"  --ipv6             follow (по умолчанию) | block | default");
    Line(L"  --no-children      не применять правило к дочерним процессам");
}

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
        return a ? std::format(L"{} {}", a->alias, guid) : std::format(L"<нет в системе> {}", guid);
    };
    Line(std::format(L"Основной интерфейс: {}",
                     config.primary == L"auto" ? std::wstring(L"auto") : adapterLabel(config.primary)));
    if (config.rules.empty()) {
        Line(L"Правил нет. Добавить: approute-config add PROGRAM --adapter IF");
        return 0;
    }
    for (const auto& rule : config.rules) {
        Line(std::format(L"{}", rule.app));
        Line(std::format(L"    → {}", adapterLabel(rule.adapter)));
        Line(std::format(L"    onUnavailable={} dns={} ipv6={} includeChildren={}", Name(rule.onUnavailable),
                         Name(rule.dns), Name(rule.ipv6), rule.includeChildren ? L"true" : L"false"));
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
    for (size_t i = 1; i < args.size(); ++i) {
        const std::wstring& arg = args[i];
        const bool hasValue = i + 1 < args.size();
        if (arg == L"--adapter" && hasValue) {
            adapterArg = args[++i];
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
        } else {
            Line(std::format(L"Ошибка: неизвестный параметр {}", arg));
            return 1;
        }
    }
    if (adapterArg.empty()) {
        Line(L"Ошибка: укажите --adapter IF");
        return 1;
    }
    // Интерфейс должен существовать сейчас: так имя/ifIndex надёжно превращаются в GUID
    const auto adapters = EnumerateAdapters();
    const auto* adapter = FindAdapter(adapters, adapterArg);
    if (!adapter) {
        Line(std::format(L"Ошибка: интерфейс «{}» не найден (см. approute-routes list)", adapterArg));
        return 1;
    }
    rule.adapter = GuidToString(adapter->guid);

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
    Line(std::format(L"{}: {} → {}", replaced ? L"Правило обновлено" : L"Правило добавлено", rule.app,
                     adapter->alias));
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
        return Remove(*config, path, args);
    }
    PrintUsage();
    return 1;
}
