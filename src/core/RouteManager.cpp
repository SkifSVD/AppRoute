#include "core/RouteManager.h"
#include "core/NetAdapters.h"
#include "core/Routes.h"
#include "core/Util.h"

#include <algorithm>
#include <format>
#include <limits>
#include <map>
#include <system_error>

namespace approute {

namespace {

const wchar_t* FamilyName(ADDRESS_FAMILY family)
{
    return family == AF_INET ? L"IPv4" : L"IPv6";
}

// Шлюз для нового маршрута 0/0 на интерфейсе: шлюз из уже существующего маршрута этого
// интерфейса (например, 0/1 от OpenVPN или маршрут в корпоративную подсеть), иначе on-link.
SOCKADDR_INET PickNextHop(const std::vector<MIB_IPFORWARD_ROW2>& routes, NET_LUID luid, ADDRESS_FAMILY family)
{
    for (const auto& r : routes) {
        if (SameLuid(r.InterfaceLuid, luid) && !IsZeroAddress(r.NextHop)) {
            return r.NextHop;
        }
    }
    SOCKADDR_INET onLink{};
    onLink.si_family = family;
    return onLink;
}

IP_ADDRESS_PREFIX DefaultPrefix(ADDRESS_FAMILY family)
{
    IP_ADDRESS_PREFIX p{};
    p.Prefix.si_family = family;
    p.PrefixLength = 0;
    return p;
}

std::wstring DescribeRoute(const MIB_IPFORWARD_ROW2& r)
{
    const auto hop = IsZeroAddress(r.NextHop) ? std::wstring(L"on-link") : FormatAddress(r.NextHop);
    return std::format(L"{} через {} [{}]", FormatPrefix(r.DestinationPrefix), hop, InterfaceName(r.InterfaceLuid));
}

bool IsBenignError(DWORD rc)
{
    return rc == ERROR_NOT_FOUND || rc == ERROR_FILE_NOT_FOUND || rc == ERROR_OBJECT_ALREADY_EXISTS;
}

} // namespace

RouteManager::RouteManager(RoutePolicy policy)
    : policy_(std::move(policy))
{
}

RoutePlan RouteManager::Plan() const
{
    RoutePlan plan;
    PlanFamily(AF_INET, plan);
    PlanFamily(AF_INET6, plan);
    return plan;
}

void RouteManager::PlanFamily(ADDRESS_FAMILY family, RoutePlan& plan) const
{
    const auto routes = GetRoutes(family);
    const NET_LUID primary = policy_.primary;

    // 1. Чем "держится" основной интерфейс.
    std::optional<ULONG64> primaryBest;   // лучшая итоговая метрика его 0/0
    bool primaryHasSplit = false;
    for (const auto& r : routes) {
        if (!SameLuid(r.InterfaceLuid, primary)) {
            continue;
        }
        if (IsDefaultRoute(r)) {
            const auto m = EffectiveMetric(r);
            primaryBest = primaryBest ? std::min(*primaryBest, m) : m;
        } else if (IsSplitDefaultRoute(r)) {
            primaryHasSplit = true;
        }
    }

    if (!primaryBest && !primaryHasSplit) {
        // Без маршрута по умолчанию на основном интерфейсе трогать ничего нельзя:
        // иначе можно оставить систему вообще без интернета.
        if (family == AF_INET || std::any_of(routes.begin(), routes.end(), IsDefaultLikeRoute)) {
            plan.warnings.push_back(std::format(
                L"{}: у основного интерфейса [{}] нет маршрута по умолчанию — {} не изменяется",
                FamilyName(family), InterfaceName(primary), FamilyName(family)));
        }
        return;
    }

    // Порог: всё, что не основной интерфейс, должно иметь итоговую метрику строго выше.
    const ULONG64 threshold = primaryBest.value_or(0);

    // Интерфейсы, у которых после выполнения плана будет 0/0, и минимальная метрика их 0/0 маршрутов.
    std::map<ULONG64, ULONG> secondaryDefaults;   // luid -> min(route metric)
    auto noteDefault = [&](NET_LUID luid, ULONG routeMetric) {
        auto [it, inserted] = secondaryDefaults.try_emplace(luid.Value, routeMetric);
        if (!inserted) {
            it->second = std::min(it->second, routeMetric);
        }
    };

    for (const auto& r : routes) {
        if (!SameLuid(r.InterfaceLuid, primary) && IsDefaultRoute(r)) {
            noteDefault(r.InterfaceLuid, r.Metric);
        }
    }

    // 2. Расщеплённые маршруты по умолчанию чужих интерфейсов: перекрывают основной по длине
    //    префикса, поэтому удаляем их и заменяем на 0/0 (с тем же шлюзом), который проиграет по метрике.
    for (const auto& r : routes) {
        if (SameLuid(r.InterfaceLuid, primary) || !IsSplitDefaultRoute(r)) {
            continue;
        }
        RouteChange del;
        del.kind = ChangeKind::DeleteRoute;
        del.route = r;
        del.description = L"удалить " + DescribeRoute(r);
        plan.changes.push_back(std::move(del));

        if (!secondaryDefaults.contains(r.InterfaceLuid.Value)) {
            RouteChange add;
            add.kind = ChangeKind::AddRoute;
            add.route = MakeRoute(r.InterfaceLuid, DefaultPrefix(family), r.NextHop, 0);
            add.description = L"добавить " + DescribeRoute(add.route);
            plan.changes.push_back(std::move(add));
            noteDefault(r.InterfaceLuid, 0);
        }
    }

    // 3. Интерфейсы, к которым будут привязываться приложения, — нужен свой 0/0.
    for (const auto& luid : policy_.ensureDefault) {
        if (SameLuid(luid, primary) || secondaryDefaults.contains(luid.Value)) {
            continue;
        }
        if (!GetIpInterface(luid, family)) {
            if (family == AF_INET) {
                plan.warnings.push_back(std::format(L"IPv4: интерфейс [{}] недоступен", InterfaceName(luid)));
            }
            continue;
        }
        RouteChange add;
        add.kind = ChangeKind::AddRoute;
        add.route = MakeRoute(luid, DefaultPrefix(family), PickNextHop(routes, luid, family), 0);
        add.description = L"добавить " + DescribeRoute(add.route);
        plan.changes.push_back(std::move(add));
        noteDefault(luid, 0);
    }

    // 4. У всех вторичных интерфейсов с 0/0 итоговая метрика должна быть выше основной.
    //    Меняем метрику ИНТЕРФЕЙСА, а не маршрута: от неё зависит ещё и порядок DNS-серверов,
    //    так что DNS по умолчанию тоже перестаёт уходить в VPN.
    //    Если основной держится только на 0/1 (глобальное переключение на VPN), 0/0 и так проигрывают.
    if (!primaryBest) {
        return;
    }
    for (const auto& [luidValue, routeMetric] : secondaryDefaults) {
        NET_LUID luid{};
        luid.Value = luidValue;
        const auto iface = GetIpInterface(luid, family);
        if (!iface) {
            continue;
        }
        if (static_cast<ULONG64>(routeMetric) + iface->Metric > threshold) {
            continue;
        }
        const ULONG64 wanted = std::max<ULONG64>(policy_.secondaryMetric, threshold + 100);
        RouteChange change;
        change.kind = ChangeKind::SetInterfaceMetric;
        change.luid = luid;
        change.family = family;
        change.oldMetric = iface->Metric;
        change.oldAutomatic = iface->UseAutomaticMetric != FALSE;
        change.newMetric = static_cast<ULONG>(std::min<ULONG64>(wanted, std::numeric_limits<ULONG>::max()));
        change.description = std::format(L"{}: метрика интерфейса [{}] {}{} → {}",
            FamilyName(family), InterfaceName(luid), iface->Metric,
            change.oldAutomatic ? L" (авто)" : L"", change.newMetric);
        plan.changes.push_back(std::move(change));
    }
}

size_t RouteManager::Apply(const std::vector<RouteChange>& changes, const LogFn& log)
{
    size_t errors = 0;
    for (const auto& c : changes) {
        DWORD rc = NO_ERROR;
        switch (c.kind) {
        case ChangeKind::DeleteRoute:
            rc = DeleteIpForwardEntry2(&c.route);
            break;
        case ChangeKind::AddRoute:
            rc = CreateIpForwardEntry2(&c.route);
            if (rc == ERROR_OBJECT_ALREADY_EXISTS) {
                continue;   // кто-то успел добавить сам — откатывать нечего
            }
            break;
        case ChangeKind::SetInterfaceMetric: {
            auto row = GetIpInterface(c.luid, c.family);
            if (!row) {
                rc = ERROR_NOT_FOUND;
                break;
            }
            row->UseAutomaticMetric = FALSE;
            row->Metric = c.newMetric;
            if (c.family == AF_INET) {
                row->SitePrefixLength = 0;   // требование SetIpInterfaceEntry для IPv4
            }
            rc = SetIpInterfaceEntry(&*row);
            break;
        }
        }

        if (rc == NO_ERROR) {
            journal_.push_back(c);
            log(L"  ✔ " + c.description);
        } else {
            ++errors;
            log(L"  ✖ " + c.description + L" — " + Win32ErrorMessage(rc));
        }
    }
    return errors;
}

void RouteManager::Revert(const LogFn& log)
{
    for (auto it = journal_.rbegin(); it != journal_.rend(); ++it) {
        const auto& c = *it;
        DWORD rc = NO_ERROR;
        std::wstring what;
        switch (c.kind) {
        case ChangeKind::DeleteRoute: {
            // Восстанавливаем "чистой" строкой: служебные поля исходной (Age, Origin) API не примет
            auto row = MakeRoute(c.route.InterfaceLuid, c.route.DestinationPrefix, c.route.NextHop, c.route.Metric);
            row.Protocol = c.route.Protocol;
            rc = CreateIpForwardEntry2(&row);
            what = L"вернуть " + DescribeRoute(c.route);
            break;
        }
        case ChangeKind::AddRoute:
            rc = DeleteIpForwardEntry2(&c.route);
            what = L"убрать " + DescribeRoute(c.route);
            break;
        case ChangeKind::SetInterfaceMetric: {
            what = std::format(L"вернуть метрику [{}] {}", InterfaceName(c.luid), c.oldMetric);
            auto row = GetIpInterface(c.luid, c.family);
            if (!row) {
                rc = ERROR_NOT_FOUND;
                break;
            }
            if (row->UseAutomaticMetric || row->Metric != c.newMetric) {
                continue;   // метрику уже поменял кто-то другой — не вмешиваемся
            }
            row->UseAutomaticMetric = c.oldAutomatic ? TRUE : FALSE;
            row->Metric = c.oldMetric;
            if (c.family == AF_INET) {
                row->SitePrefixLength = 0;
            }
            rc = SetIpInterfaceEntry(&*row);
            break;
        }
        }

        if (rc == NO_ERROR) {
            log(L"  ↺ " + what);
        } else if (!IsBenignError(rc)) {
            log(L"  ✖ " + what + L" — " + Win32ErrorMessage(rc));
        }
    }
    journal_.clear();
}

std::optional<NET_LUID> DetectPrimaryInterface()
{
    const auto adapters = EnumerateAdapters();
    const auto routes = GetRoutes(AF_INET);

    std::optional<NET_LUID> best;
    ULONG64 bestMetric = std::numeric_limits<ULONG64>::max();
    for (const auto& r : routes) {
        if (!IsDefaultRoute(r)) {
            continue;
        }
        const auto* a = FindAdapter(adapters, r.InterfaceLuid);
        if (!a || !a->hardware || !a->IsUp()) {
            continue;
        }
        const auto m = EffectiveMetric(r);
        if (m < bestMetric) {
            bestMetric = m;
            best = r.InterfaceLuid;
        }
    }
    return best;
}

// --- ChangeNotifier ---------------------------------------------------------------------------

ChangeNotifier::ChangeNotifier()
{
    event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event_) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "CreateEventW");
    }
    DWORD rc = NotifyRouteChange2(AF_UNSPEC, &ChangeNotifier::OnRouteChange, this, FALSE, &routeHandle_);
    if (rc == NO_ERROR) {
        rc = NotifyIpInterfaceChange(AF_UNSPEC, &ChangeNotifier::OnInterfaceChange, this, FALSE, &interfaceHandle_);
    }
    if (rc != NO_ERROR) {
        Close();
        throw std::system_error(static_cast<int>(rc), std::system_category(), "NotifyRouteChange2");
    }
}

ChangeNotifier::~ChangeNotifier()
{
    Close();
}

void ChangeNotifier::Close()
{
    if (routeHandle_) {
        CancelMibChangeNotify2(routeHandle_);
        routeHandle_ = nullptr;
    }
    if (interfaceHandle_) {
        CancelMibChangeNotify2(interfaceHandle_);
        interfaceHandle_ = nullptr;
    }
    if (event_) {
        CloseHandle(event_);
        event_ = nullptr;
    }
}

VOID NETIOAPI_API_ ChangeNotifier::OnRouteChange(PVOID context, PMIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE)
{
    SetEvent(static_cast<ChangeNotifier*>(context)->event_);
}

VOID NETIOAPI_API_ ChangeNotifier::OnInterfaceChange(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
    SetEvent(static_cast<ChangeNotifier*>(context)->event_);
}

} // namespace approute
