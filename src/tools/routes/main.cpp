// approute-routes — консольный прототип менеджера маршрутов AppRoute.
//
//   approute-routes list
//   approute-routes plan  [--primary <интерфейс>] [--ensure-default <интерфейс>]... [--metric N]
//   approute-routes watch [--primary <интерфейс>] [--ensure-default <интерфейс>]... [--metric N]
//
// <интерфейс> — ifIndex, GUID или имя (как в "Сетевых подключениях").
// watch применяет политику, следит за изменениями (переподключение VPN) и откатывает всё
// при выходе (Ctrl+C / закрытие окна). Изменения не переживают перезагрузку.

#include "core/NetAdapters.h"
#include "core/RouteManager.h"
#include "core/Routes.h"
#include "core/Util.h"

#include <algorithm>
#include <exception>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace approute;

namespace {

// --- вывод ----------------------------------------------------------------------------------

void Out(std::wstring_view text)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    // Вывод перенаправлен в файл/канал — пишем UTF-8
    const int len = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), len, nullptr, nullptr);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void Line(std::wstring_view text = {})
{
    Out(text);
    Out(L"\n");
}

// Текст исключения (std::system_error пишет в кодировке ANSI) → UTF-16
std::wstring Widen(const char* text)
{
    const int len = MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(len > 0 ? len - 1 : 0), L'\0');
    if (len > 1) {
        MultiByteToWideChar(CP_ACP, 0, text, -1, out.data(), len);
    }
    return out;
}

std::wstring Now()
{
    SYSTEMTIME t{};
    GetLocalTime(&t);
    return std::format(L"{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond);
}

std::wstring FirstAddress(const NetAdapter& a, ADDRESS_FAMILY family, bool withPrefix)
{
    for (const auto& u : a.unicast) {
        if (u.address.si_family == family) {
            return withPrefix ? std::format(L"{}/{}", FormatAddress(u.address), u.prefixLength)
                              : FormatAddress(u.address);
        }
    }
    return L"-";
}

std::wstring FirstGateway(const NetAdapter& a, ADDRESS_FAMILY family)
{
    for (const auto& g : a.gateways) {
        if (g.si_family == family) {
            return FormatAddress(g);
        }
    }
    return L"-";
}

// --- аргументы ------------------------------------------------------------------------------

struct Options {
    std::wstring command;
    std::optional<std::wstring> primary;
    std::vector<std::wstring> ensureDefault;
    std::vector<std::wstring> routes;   // "PREFIX=IF"
    std::optional<ULONG> metric;
};

void PrintUsage()
{
    Line(L"approute-routes — прототип менеджера маршрутов AppRoute");
    Line();
    Line(L"  approute-routes list");
    Line(L"      адаптеры, маршруты по умолчанию и текущий выход в интернет");
    Line(L"  approute-routes plan  [--primary IF] [--ensure-default IF]... [--route PREFIX=IF]... [--metric N]");
    Line(L"      показать, что будет изменено (ничего не меняет)");
    Line(L"  approute-routes watch [--primary IF] [--ensure-default IF]... [--route PREFIX=IF]... [--metric N]");
    Line(L"      применить и поддерживать политику; Ctrl+C — откатить и выйти (нужны права администратора)");
    Line();
    Line(L"  IF — ifIndex, GUID или имя интерфейса.");
    Line(L"  --primary         через этот интерфейс идёт весь трафик (по умолчанию — физический с лучшей метрикой)");
    Line(L"  --ensure-default  добавить на интерфейс маршрут 0/0 с низким приоритетом (для привязки приложений)");
    Line(L"  --route           закрепить подсеть за интерфейсом, например 160.79.104.0/23=happ-xray:");
    Line(L"                    трафик всех программ в эту подсеть идёт через него, остальной — как обычно");
    Line(L"  --metric          метрика для вторичных интерфейсов (по умолчанию 5000)");
}

std::optional<Options> ParseArgs(int argc, wchar_t** argv)
{
    if (argc < 2) {
        return std::nullopt;
    }
    Options o;
    o.command = argv[1];
    for (int i = 2; i < argc; ++i) {
        const std::wstring_view arg = argv[i];
        auto value = [&]() -> std::optional<std::wstring> {
            if (i + 1 >= argc) {
                Line(std::format(L"Ошибка: после {} нужно значение", arg));
                return std::nullopt;
            }
            return std::wstring(argv[++i]);
        };
        if (arg == L"--primary") {
            auto v = value();
            if (!v) return std::nullopt;
            o.primary = *v;
        } else if (arg == L"--ensure-default") {
            auto v = value();
            if (!v) return std::nullopt;
            o.ensureDefault.push_back(*v);
        } else if (arg == L"--route") {
            auto v = value();
            if (!v) return std::nullopt;
            o.routes.push_back(*v);
        } else if (arg == L"--metric") {
            auto v = value();
            if (!v) return std::nullopt;
            o.metric = static_cast<ULONG>(std::wcstoul(v->c_str(), nullptr, 10));
        } else {
            Line(std::format(L"Ошибка: неизвестный параметр {}", arg));
            return std::nullopt;
        }
    }
    return o;
}

std::optional<RoutePolicy> BuildPolicy(const Options& o)
{
    const auto adapters = EnumerateAdapters();
    RoutePolicy policy;

    if (o.primary) {
        const auto* a = FindAdapter(adapters, *o.primary);
        if (!a) {
            Line(std::format(L"Ошибка: интерфейс «{}» не найден (см. approute-routes list)", *o.primary));
            return std::nullopt;
        }
        policy.primary = a->luid;
    } else {
        const auto detected = DetectPrimaryInterface();
        if (!detected) {
            Line(L"Ошибка: не удалось определить основной физический интерфейс, укажите --primary");
            return std::nullopt;
        }
        policy.primary = *detected;
    }

    for (const auto& key : o.ensureDefault) {
        const auto* a = FindAdapter(adapters, key);
        if (!a) {
            Line(std::format(L"Ошибка: интерфейс «{}» не найден", key));
            return std::nullopt;
        }
        policy.ensureDefault.push_back(a->luid);
    }
    for (const auto& spec : o.routes) {
        const auto eq = spec.find(L'=');
        const auto prefix = eq == std::wstring::npos ? std::nullopt : ParsePrefix(std::wstring_view(spec).substr(0, eq));
        if (!prefix) {
            Line(std::format(L"Ошибка: --route {} — ожидалось ПОДСЕТЬ=ИНТЕРФЕЙС, например 160.79.104.0/23=happ-xray", spec));
            return std::nullopt;
        }
        if (prefix->PrefixLength == 0) {
            Line(L"Ошибка: --route не для маршрута по умолчанию — используйте --primary");
            return std::nullopt;
        }
        const auto* a = FindAdapter(adapters, spec.substr(eq + 1));
        if (!a) {
            Line(std::format(L"Ошибка: интерфейс «{}» не найден", spec.substr(eq + 1)));
            return std::nullopt;
        }
        policy.pinned.push_back({*prefix, a->luid});
    }
    if (o.metric) {
        policy.secondaryMetric = *o.metric;
    }
    return policy;
}

// --- list -----------------------------------------------------------------------------------

void PrintInternetPath(ADDRESS_FAMILY family, const wchar_t* probe)
{
    SOCKADDR_INET dest{};
    dest.si_family = family;
    if (family == AF_INET) {
        InetPtonW(AF_INET, probe, &dest.Ipv4.sin_addr);
    } else {
        InetPtonW(AF_INET6, probe, &dest.Ipv6.sin6_addr);
    }
    const auto best = BestRouteTo(dest);
    Line(std::format(L"Выход в интернет {}: {}", family == AF_INET ? L"IPv4" : L"IPv6",
        best ? std::format(L"[{}] по маршруту {}", InterfaceName(best->InterfaceLuid), FormatPrefix(best->DestinationPrefix))
             : std::wstring(L"нет маршрута")));
}

void PrintDefaultRoutes(ADDRESS_FAMILY family)
{
    auto routes = GetRoutes(family);
    std::erase_if(routes, [](const auto& r) { return !IsDefaultLikeRoute(r); });
    if (routes.empty()) {
        return;
    }
    std::sort(routes.begin(), routes.end(), [](const auto& a, const auto& b) {
        if (a.DestinationPrefix.PrefixLength != b.DestinationPrefix.PrefixLength) {
            return a.DestinationPrefix.PrefixLength > b.DestinationPrefix.PrefixLength;
        }
        return EffectiveMetric(a) < EffectiveMetric(b);
    });

    Line();
    Line(std::format(L"Маршруты по умолчанию {} (сверху — побеждающие):", family == AF_INET ? L"IPv4" : L"IPv6"));
    for (const auto& r : routes) {
        const auto ifMetric = GetInterfaceMetric(r.InterfaceLuid, family).value_or(0);
        Line(std::format(L"  {:<14} {:<26} шлюз {:<16} метрика {} + {} = {}",
            FormatPrefix(r.DestinationPrefix), InterfaceName(r.InterfaceLuid),
            IsZeroAddress(r.NextHop) ? std::wstring(L"on-link") : FormatAddress(r.NextHop),
            r.Metric, ifMetric, static_cast<ULONG64>(r.Metric) + ifMetric));
    }
}

int CmdList()
{
    const auto adapters = EnumerateAdapters();

    Line(L"Подключённые адаптеры:");
    Line(std::format(L"  {:>4}  {:<30} {:<5} {:<20} {:<16} {:>7}", L"#", L"Имя", L"Тип", L"IPv4", L"Шлюз", L"Метрика"));
    size_t hidden = 0;
    for (const auto& a : adapters) {
        if (!a.IsUp()) {
            ++hidden;
            continue;
        }
        const auto metric = GetInterfaceMetric(a.luid, AF_INET);
        Line(std::format(L"  {:>4}  {:<30} {:<5} {:<20} {:<16} {:>7}",
            a.ifIndex, a.alias, a.hardware ? L"физ." : L"вирт.",
            FirstAddress(a, AF_INET, true), FirstGateway(a, AF_INET),
            metric ? std::to_wstring(*metric) : std::wstring(L"-")));
        Line(std::format(L"        {}  {}", GuidToString(a.guid), a.description));
    }
    if (hidden) {
        Line(std::format(L"  (+{} отключённых адаптеров не показано)", hidden));
    }

    PrintDefaultRoutes(AF_INET);
    PrintDefaultRoutes(AF_INET6);

    Line();
    PrintInternetPath(AF_INET, L"1.1.1.1");
    PrintInternetPath(AF_INET6, L"2606:4700:4700::1111");

    if (const auto primary = DetectPrimaryInterface()) {
        Line(std::format(L"Основной физический интерфейс (авто): [{}]", InterfaceName(*primary)));
    }
    return 0;
}

// --- plan / watch ---------------------------------------------------------------------------

void PrintPolicy(const RoutePolicy& p)
{
    Line(std::format(L"Основной интерфейс: [{}]", InterfaceName(p.primary)));
    for (const auto& luid : p.ensureDefault) {
        Line(std::format(L"Маршрут 0/0 с низким приоритетом: [{}]", InterfaceName(luid)));
    }
    for (const auto& pin : p.pinned) {
        Line(std::format(L"Подсеть {} закреплена за [{}]", FormatPrefix(pin.prefix), InterfaceName(pin.luid)));
    }
    Line(std::format(L"Метрика вторичных интерфейсов: {}", p.secondaryMetric));
}

void PrintWarnings(const std::vector<std::wstring>& warnings)
{
    for (const auto& w : warnings) {
        Line(L"  ⚠ " + w);
    }
}

int CmdPlan(const RoutePolicy& policy)
{
    PrintPolicy(policy);
    const RouteManager manager(policy);
    const auto plan = manager.Plan();
    Line();
    PrintWarnings(plan.warnings);
    if (plan.changes.empty()) {
        Line(L"Изменения не нужны: система уже соответствует политике.");
        return 0;
    }
    Line(L"Будет изменено:");
    for (const auto& c : plan.changes) {
        Line(L"  • " + c.description);
    }
    return 0;
}

HANDLE g_stop = nullptr;
HANDLE g_done = nullptr;

BOOL WINAPI CtrlHandler(DWORD type)
{
    SetEvent(g_stop);
    if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        // После возврата процесс будет убит — даём основному потоку откатить изменения
        WaitForSingleObject(g_done, 4000);
    }
    return TRUE;
}

int CmdWatch(const RoutePolicy& policy)
{
    if (!IsProcessElevated()) {
        Line(L"Ошибка: для изменения маршрутов нужны права администратора.");
        Line(L"Запустите терминал «от имени администратора» и повторите команду.");
        return 2;
    }

    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    PrintPolicy(policy);
    Line(L"Слежу за изменениями маршрутов. Ctrl+C — откатить изменения и выйти.");
    Line();

    RouteManager manager(policy);
    ChangeNotifier notifier;
    std::vector<std::wstring> lastWarnings;

    auto log = [](std::wstring_view s) { Line(s); };
    auto pass = [&] {
        try {
            const auto plan = manager.Plan();
            if (plan.warnings != lastWarnings) {
                PrintWarnings(plan.warnings);
                lastWarnings = plan.warnings;
            }
            if (!plan.changes.empty()) {
                Line(std::format(L"[{}] исправляю маршруты:", Now()));
                manager.Apply(plan.changes, log);
            }
        } catch (const std::exception& e) {
            Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
        }
    };

    pass();
    const HANDLE handles[] = {g_stop, notifier.Event()};
    for (;;) {
        const DWORD w = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0) {
            break;
        }
        // Дебаунс: VPN-клиенты меняют маршруты пачкой, ждём, пока всё уляжется
        if (WaitForSingleObject(g_stop, 300) == WAIT_OBJECT_0) {
            break;
        }
        ResetEvent(notifier.Event());
        pass();
    }

    Line();
    Line(std::format(L"[{}] откатываю изменения…", Now()));
    manager.Revert(log);
    Line(L"Готово.");
    SetEvent(g_done);
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    const auto options = ParseArgs(argc, argv);
    if (!options) {
        PrintUsage();
        return 1;
    }

    try {
        if (options->command == L"list") {
            return CmdList();
        }
        if (options->command == L"plan" || options->command == L"watch") {
            const auto policy = BuildPolicy(*options);
            if (!policy) {
                return 1;
            }
            return options->command == L"plan" ? CmdPlan(*policy) : CmdWatch(*policy);
        }
        PrintUsage();
        return 1;
    } catch (const std::exception& e) {
        Line(std::format(L"Ошибка: {}", Widen(e.what())));
        return 1;
    }
}
