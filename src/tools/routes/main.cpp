// approute-routes — консольный прототип менеджера маршрутов AppRoute.
//
//   approute-routes list
//   approute-routes plan  [--primary <интерфейс>] [--ensure-default <интерфейс>]... [--metric N]
//   approute-routes watch [--primary <интерфейс>] [--ensure-default <интерфейс>]... [--metric N]
//                         [--config FILE]
//   approute-routes serve [--config FILE] [--client-sid SID]
//   approute-routes install-service [--config FILE] [--client-sid SID]
//   approute-routes uninstall-service
//   approute-routes service --config FILE --client-sid SID   (запускает диспетчер служб)
//
// Служба (#16) — тот же менеджер маршрутов, работающий постоянно: ставится только явно
// (install-service из approute-gui после согласия и UAC), удаляется uninstall-service.
//
// serve — менеджер маршрутов, запущенный из approute-gui с согласия пользователя (#15): без
// консоли, журнал в %LOCALAPPDATA%\AppRoute\routes.log, вся политика из конфига (основной
// интерфейс, 0/0 на интерфейсах правил, закреплённые подсети), управление — по каналу.
// Без --primary основной интерфейс берётся из поля "primary" конфига (глобальный
// переключатель, #14); watch перечитывает конфиг при изменении и переключается на лету.
// <интерфейс> — ifIndex, GUID или имя (как в "Сетевых подключениях").
// watch применяет политику, следит за изменениями (переподключение VPN) и откатывает всё
// при выходе (Ctrl+C / закрытие окна). Изменения не переживают перезагрузку.

#include "core/Config.h"
#include "core/ConfigPolicy.h"
#include "core/Json.h"
#include "core/ManagerPipe.h"
#include "core/NetAdapters.h"
#include "core/PrimarySwitch.h"
#include "core/ConflictGuard.h"
#include "core/RouteManager.h"
#include "core/ServiceSetup.h"
#include "core/Routes.h"
#include "core/Util.h"

#include <algorithm>
#include <mutex>
#include <exception>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace approute;

namespace {

// --- вывод ----------------------------------------------------------------------------------

HANDLE g_logFile = nullptr;   // serve: журнал вместо консоли

void Out(std::wstring_view text)
{
    HANDLE h = g_logFile ? g_logFile : GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (!g_logFile && GetConsoleMode(h, &mode)) {
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
    std::wstring config;                // файл правил; пусто — по умолчанию
    std::wstring clientSid;             // serve: пользователь, которому доступен канал
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
    Line(L"  approute-routes serve [--config FILE]");
    Line(L"      менеджер маршрутов для approute-gui: без консоли, политика из конфига, журнал");
    Line(L"      %LOCALAPPDATA%\\AppRoute\\routes.log; запускается из окна с вашего согласия");
    Line(L"  approute-routes install-service [--config FILE]");
    Line(L"      установить менеджер маршрутов службой Windows: работает постоянно, в том числе после");
    Line(L"      перезагрузки; файлы копируются в %ProgramFiles%\\AppRoute (нужны права администратора)");
    Line(L"  approute-routes uninstall-service");
    Line(L"      остановить службу (изменения откатываются) и удалить её");
    Line();
    Line(L"  IF — ifIndex, GUID или имя интерфейса.");
    Line(L"  --primary         через этот интерфейс идёт весь трафик; без параметра — из конфига (\"primary\",");
    Line(L"                    переключатель в approute-gui), \"auto\" — физический с лучшей метрикой");
    Line(L"  --config          файл правил (по умолчанию %APPDATA%\\AppRoute\\config.json)");
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
        } else if (arg == L"--client-sid") {
            auto v = value();
            if (!v) return std::nullopt;
            o.clientSid = *v;
        } else if (arg == L"--config") {
            auto v = value();
            if (!v) return std::nullopt;
            o.config = *v;
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

std::wstring ConfigPath(const Options& o)
{
    return o.config.empty() ? DefaultConfigPath() : o.config;
}

// Основной интерфейс из конфига (переключатель #14). note — пояснение (недоступен, конфиг не
// прочитан), печатает вызывающий.
std::optional<NET_LUID> PrimaryFromConfig(const Options& o, const std::vector<NetAdapter>& adapters,
                                          std::wstring& note)
{
    std::wstring configured = L"auto";
    std::wstring error;
    if (const auto config = LoadConfig(ConfigPath(o), &error)) {
        configured = config->primary;
    } else {
        note = L"конфиг не прочитан, основной интерфейс — автоматически: " + error;
    }
    const auto choice = ChoosePrimary(configured, adapters, DetectPrimaryInterface(), InterfacesWithInternetRoute());
    if (!choice.note.empty()) {
        note = choice.note;
    }
    return choice.luid;
}

std::optional<RoutePolicy> BuildPolicy(const Options& o, std::wstring* primaryNote = nullptr)
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
        std::wstring note;
        const auto primary = PrimaryFromConfig(o, adapters, note);
        if (primaryNote) {
            *primaryNote = note;
        } else if (!note.empty()) {
            Line(L"⚠ " + note);
        }
        if (!primary) {
            Line(L"Ошибка: не удалось определить основной физический интерфейс, укажите --primary");
            return std::nullopt;
        }
        policy.primary = *primary;
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

int CmdWatch(const Options& options)
{
    if (!IsProcessElevated()) {
        Line(L"Ошибка: для изменения маршрутов нужны права администратора.");
        Line(L"Запустите терминал «от имени администратора» и повторите команду.");
        return 2;
    }
    // Один менеджер маршрутов на сеанс; по мьютексу его видит и approute-gui
    const HANDLE single = CreateMutexW(nullptr, FALSE, kRouteManagerMutex);
    if (single && GetLastError() == ERROR_ALREADY_EXISTS) {
        Line(L"Ошибка: менеджер маршрутов уже запущен (служба AppRoute, окно approute-gui или другое approute-routes watch).");
        CloseHandle(single);
        return 1;
    }
    std::wstring primaryNote;
    const auto initial = BuildPolicy(options, &primaryNote);
    if (!initial) {
        return 1;
    }
    const RoutePolicy& policy = *initial;

    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    PrintPolicy(policy);
    if (!primaryNote.empty()) {
        Line(L"⚠ " + primaryNote);
    }
    const bool switchable = !options.primary;
    if (switchable) {
        Line(std::format(L"Основной интерфейс — из {} (переключатель в approute-gui).", ConfigPath(options)));
    }
    Line(L"Слежу за изменениями маршрутов. Ctrl+C — откатить изменения и выйти.");
    Line();

    RouteManager manager(policy);
    ChangeNotifier notifier;
    ConflictGuard guard;   // защита от «войны метрик» с VPN-клиентом (#2)
    std::vector<std::wstring> lastWarnings;

    auto log = [](std::wstring_view s) { Line(s); };
    auto pass = [&] {
        try {
            const auto plan = manager.Plan();
            if (plan.warnings != lastWarnings) {
                PrintWarnings(plan.warnings);
                lastWarnings = plan.warnings;
            }
            std::vector<std::wstring> conflicts;
            const auto changes = guard.Filter(plan.changes, GetTickCount64(), conflicts);
            for (const auto& message : conflicts) {
                Line(std::format(L"[{}] ⚠ {}", Now(), message));
            }
            if (!changes.empty()) {
                Line(std::format(L"[{}] исправляю маршруты:", Now()));
                manager.Apply(changes, log);
            }
        } catch (const std::exception& e) {
            Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
        }
    };

    // Переключатель (#14): основной интерфейс из конфига мог смениться (выбор в GUI) или стать
    // недоступным (выбранный VPN отключился). Смена — откат изменений старой политики и
    // применение новой; правила приложений это не затрагивает.
    std::wstring lastNote = primaryNote;
    auto followPrimary = [&] {
        if (!switchable) {
            return;
        }
        try {
            std::wstring note;
            const auto next = BuildPolicy(options, &note);
            if (note != lastNote && !note.empty()) {
                Line(std::format(L"[{}] ⚠ {}", Now(), note));
            }
            lastNote = note;
            if (!next || SameLuid(next->primary, manager.Policy().primary)) {
                return;
            }
            Line(std::format(L"[{}] основной интерфейс: [{}] → [{}]", Now(), InterfaceName(manager.Policy().primary),
                             InterfaceName(next->primary)));
            manager.Revert(log);
            manager = RouteManager(*next);
            guard = ConflictGuard{};
        } catch (const std::exception& e) {
            Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
        }
    };

    std::optional<FileChangeWatcher> configWatch;
    if (switchable) {
        configWatch.emplace(ConfigPath(options));
    }
    pass();
    std::vector<HANDLE> handles = {g_stop, notifier.Event()};
    if (configWatch && configWatch->Event()) {
        handles.push_back(configWatch->Event());
    }
    for (;;) {
        const DWORD w = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
        if (w == WAIT_OBJECT_0) {
            break;
        }
        // Дебаунс: VPN-клиенты меняют маршруты пачкой, ждём, пока всё уляжется
        if (WaitForSingleObject(g_stop, 300) == WAIT_OBJECT_0) {
            break;
        }
        ResetEvent(notifier.Event());
        if (configWatch) {
            configWatch->Rearm();
        }
        followPrimary();
        pass();
    }

    Line();
    Line(std::format(L"[{}] откатываю изменения…", Now()));
    manager.Revert(log);
    Line(L"Готово.");
    if (single) {
        CloseHandle(single);
    }
    SetEvent(g_done);
    return 0;
}

// --- serve (#15) ----------------------------------------------------------------------------

std::wstring ThisDirectory()
{
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())));
    return path.substr(0, path.find_last_of(L'\\'));
}

// %LOCALAPPDATA%\AppRoute\routes.log, предыдущий — routes.log.1 (больше 1 МБ)
HANDLE OpenServeLog()
{
    wchar_t local[MAX_PATH * 2] = {};
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)))) {
        return nullptr;
    }
    const std::wstring dir = std::wstring(local) + L"\\AppRoute";
    CreateDirectoryW(dir.c_str(), nullptr);
    const std::wstring log = dir + L"\\routes.log";
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (GetFileAttributesExW(log.c_str(), GetFileExInfoStandard, &info) && (info.nFileSizeHigh || info.nFileSizeLow > 1024 * 1024)) {
        MoveFileExW(log.c_str(), (log + L".1").c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    const HANDLE h = CreateFileW(log.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h == INVALID_HANDLE_VALUE ? nullptr : h;
}

// Менеджер маршрутов без консоли — для serve (канал с approute-gui) и службы (#16, без канала:
// ею управляет диспетчер служб). g_stop должен быть создан. 0 — штатная остановка.
int RunManager(const Options& options, bool withPipe, const wchar_t* who)
{
    if (!IsProcessElevated()) {
        Line(L"Ошибка: для изменения маршрутов нужны права администратора.");
        return 2;
    }
    // Один менеджер маршрутов на компьютер (Global\): служба, serve или watch
    const HANDLE single = CreateMutexW(nullptr, FALSE, kRouteManagerMutex);
    if (!single || GetLastError() == ERROR_ALREADY_EXISTS) {
        Line(std::format(L"[{}] менеджер маршрутов уже запущен — выход", Now()));
        if (single) {
            CloseHandle(single);
        }
        return 1;
    }

    const std::wstring configPath = ConfigPath(options);
    Line();
    Line(std::format(L"[{}] {} запущен (PID {}), правила: {}", Now(), who, GetCurrentProcessId(), configPath));

    // Состояние для approute-gui (запрос STATUS)
    std::mutex statusLock;
    std::string status = "{}";
    const auto setStatus = [&](const RoutePolicy* policy, const std::vector<std::wstring>& notes) {
        json::Object o;
        o.emplace_back("pid", static_cast<double>(GetCurrentProcessId()));
        o.emplace_back("primary", policy ? ToUtf8(InterfaceName(policy->primary)) : std::string());
        json::Array n;
        for (const auto& s : notes) {
            n.emplace_back(ToUtf8(s));
        }
        o.emplace_back("notes", std::move(n));
        std::lock_guard lock(statusLock);
        status = json::Serialize(json::Value(std::move(o)));
    };

    // Канал: только approute-gui из этой папки под пользователем, который дал согласие
    const std::wstring clientSid = options.clientSid.empty() ? CurrentUserSid() : options.clientSid;
    ManagerPipeServer pipe(ManagerPipeName(), clientSid, ThisDirectory() + L"\\approute-gui.exe",
                           [&](std::string_view request) -> std::string {
                               if (request == "STOP") {
                                   Line(std::format(L"[{}] остановка по запросу approute-gui", Now()));
                                   SetEvent(g_stop);
                                   return "{\"ok\":true}";
                               }
                               if (request == "STATUS") {
                                   std::lock_guard lock(statusLock);
                                   return status;
                               }
                               return "{\"error\":\"unknown\"}";
                           });
    std::wstring pipeError;
    if (withPipe && !pipe.Start(&pipeError)) {
        // Без канала окно не сможет остановить менеджер — не запускаемся
        Line(std::format(L"[{}] ошибка: {}", Now(), pipeError));
        CloseHandle(single);
        return 1;
    }

    std::optional<RouteManager> manager;
    ConflictGuard guard;
    std::vector<std::wstring> lastWarnings;
    std::vector<std::wstring> lastNotes;
    auto log = [](std::wstring_view s) { Line(s); };

    // Политика из конфига; изменилась (переключатель, правила, подсети, появился VPN) —
    // откат старой и применение новой. Конфиг не читается — действует прежняя политика.
    auto follow = [&] {
        try {
            std::wstring error;
            const auto config = LoadConfig(configPath, &error);
            if (!config) {
                Line(std::format(L"[{}] ⚠ конфиг не прочитан, политика не меняется: {}", Now(), error));
                return;
            }
            const auto next = PolicyFromConfig(*config);
            if (next.notes != lastNotes) {
                for (const auto& n : next.notes) {
                    Line(std::format(L"[{}] ⚠ {}", Now(), n));
                }
                lastNotes = next.notes;
            }
            if (!next.policy) {
                return;
            }
            if (manager && SamePolicy(manager->Policy(), *next.policy)) {
                setStatus(&manager->Policy(), next.notes);
                return;
            }
            if (manager) {
                Line(std::format(L"[{}] политика изменилась, основной интерфейс: [{}] → [{}]", Now(),
                                 InterfaceName(manager->Policy().primary), InterfaceName(next.policy->primary)));
                manager->Revert(log);
            }
            PrintPolicy(*next.policy);
            manager.emplace(*next.policy);
            guard = ConflictGuard{};
            setStatus(&manager->Policy(), next.notes);
        } catch (const std::exception& e) {
            Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
        }
    };
    auto pass = [&] {
        if (!manager) {
            return;
        }
        try {
            const auto plan = manager->Plan();
            if (plan.warnings != lastWarnings) {
                PrintWarnings(plan.warnings);
                lastWarnings = plan.warnings;
            }
            std::vector<std::wstring> conflicts;
            const auto changes = guard.Filter(plan.changes, GetTickCount64(), conflicts);
            for (const auto& message : conflicts) {
                Line(std::format(L"[{}] ⚠ {}", Now(), message));
            }
            if (!changes.empty()) {
                Line(std::format(L"[{}] исправляю маршруты:", Now()));
                manager->Apply(changes, log);
            }
        } catch (const std::exception& e) {
            Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
        }
    };

    ChangeNotifier notifier;
    FileChangeWatcher configWatch(configPath);
    follow();
    pass();
    std::vector<HANDLE> handles = {g_stop, notifier.Event()};
    if (configWatch.Event()) {
        handles.push_back(configWatch.Event());
    }
    for (;;) {
        const DWORD w = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 || WaitForSingleObject(g_stop, 300) == WAIT_OBJECT_0) {
            break;
        }
        ResetEvent(notifier.Event());
        configWatch.Rearm();
        follow();
        pass();
    }

    pipe.Stop();
    Line(std::format(L"[{}] откатываю изменения…", Now()));
    if (manager) {
        manager->Revert(log);
    }
    Line(std::format(L"[{}] {} остановлен", Now(), who));
    CloseHandle(single);
    return 0;
}

int CmdServe(const Options& options)
{
    g_logFile = OpenServeLog();
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    const int code = RunManager(options, true, L"менеджер маршрутов");
    SetEvent(g_done);
    return code;
}

// --- служба (#16) ---------------------------------------------------------------------------

Options g_serviceOptions;
SERVICE_STATUS_HANDLE g_serviceStatus = nullptr;
SERVICE_STATUS g_status{SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0};

void ReportService(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0)
{
    static DWORD checkPoint = 1;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
    SetServiceStatus(g_serviceStatus, &g_status);
}

DWORD WINAPI ServiceControl(DWORD control, DWORD, void*, void*)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportService(SERVICE_STOP_PENDING, NO_ERROR, 15000);   // откат маршрутов
        SetEvent(g_stop);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

std::wstring ProgramDataDirectory()
{
    wchar_t data[MAX_PATH * 2] = {};
    if (!GetEnvironmentVariableW(L"ProgramData", data, static_cast<DWORD>(std::size(data)))) {
        return {};
    }
    return std::wstring(data) + L"\\AppRoute";
}

void WINAPI ServiceMain(DWORD, wchar_t**)
{
    g_serviceStatus = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControl, nullptr);
    if (!g_serviceStatus) {
        return;
    }
    ReportService(SERVICE_START_PENDING, NO_ERROR, 5000);
    // Журнал — в защищённой папке (читать могут пользователи, писать — только SYSTEM и
    // администраторы); не открылся безопасно — работаем без журнала
    const std::wstring dir = ProgramDataDirectory();
    if (!dir.empty()) {
        g_logFile = OpenProtectedLog(dir, L"routes.log");
    }
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ReportService(SERVICE_RUNNING);
    int code = 1;
    try {
        code = RunManager(g_serviceOptions, false, L"служба AppRoute");
    } catch (const std::exception& e) {
        Line(std::format(L"[{}] ошибка: {}", Now(), Widen(e.what())));
    }
    if (g_logFile) {
        CloseHandle(g_logFile);
        g_logFile = nullptr;
    }
    // Ненулевой код — диспетчер служб перезапустит службу (действия при сбое)
    ReportService(SERVICE_STOPPED, code == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

int CmdService(const Options& options)
{
    if (options.config.empty()) {
        Line(L"Ошибка: службе нужен --config (файл правил пользователя).");
        return 1;
    }
    g_serviceOptions = options;
    wchar_t name[] = L"AppRoute";
    SERVICE_TABLE_ENTRYW table[] = {{name, ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        Line(L"Ошибка: команду service запускает диспетчер служб Windows. Установка — install-service.");
        return 1;
    }
    return 0;
}

int CmdInstallService(const Options& options)
{
    if (!IsProcessElevated()) {
        Line(L"Ошибка: для установки службы нужны права администратора.");
        return 2;
    }
    const std::wstring sid = options.clientSid.empty() ? CurrentUserSid() : options.clientSid;
    const std::wstring config = ConfigPath(options);
    std::wstring error;
    if (!InstallAppRouteService(ThisDirectory(), config, sid, &error)) {
        Line(L"Ошибка: " + error);
        return 1;
    }
    Line(std::format(L"Служба AppRoute установлена в {} и запущена; правила: {}", InstallDirectory(), config));
    Line(L"Журнал: %ProgramData%\\AppRoute\\routes.log. Удаление — approute-routes uninstall-service.");
    return 0;
}

int CmdUninstallService()
{
    if (!IsProcessElevated()) {
        Line(L"Ошибка: для удаления службы нужны права администратора.");
        return 2;
    }
    std::wstring error;
    if (!UninstallAppRouteService(&error)) {
        Line(L"Ошибка: " + error);
        return 1;
    }
    Line(L"Служба AppRoute остановлена (изменения маршрутов откачены) и удалена.");
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
        if (options->command == L"watch") {
            return CmdWatch(*options);
        }
        if (options->command == L"serve") {
            return CmdServe(*options);
        }
        if (options->command == L"service") {
            return CmdService(*options);
        }
        if (options->command == L"install-service") {
            return CmdInstallService(*options);
        }
        if (options->command == L"uninstall-service") {
            return CmdUninstallService();
        }
        if (options->command == L"plan") {
            const auto policy = BuildPolicy(*options);
            if (!policy) {
                return 1;
            }
            return CmdPlan(*policy);
        }
        PrintUsage();
        return 1;
    } catch (const std::exception& e) {
        Line(std::format(L"Ошибка: {}", Widen(e.what())));
        return 1;
    }
}
