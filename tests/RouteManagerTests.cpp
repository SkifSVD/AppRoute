// Тесты RouteManager::Plan по снимку состояния (issue #4): система не читается и не меняется.
// Адреса — из документационных диапазонов (RFC 5737, RFC 3849) и частных сетей.

#include "core/RouteManager.h"
#include "core/Routes.h"
#include "core/Util.h"

#include "Test.h"

#include <algorithm>

using namespace approute;

namespace {

NET_LUID Luid(ULONG64 value)
{
    NET_LUID luid{};
    luid.Value = value;
    return luid;
}

const NET_LUID kWifi = Luid(0x1001);      // основной физический интерфейс
const NET_LUID kOpenVpn = Luid(0x2002);   // OpenVPN (0/1 + 128/1)
const NET_LUID kHapp = Luid(0x3003);      // TUN-клиент с 0/0 и низкой метрикой

SOCKADDR_INET Addr(const wchar_t* text)
{
    SOCKADDR_INET a{};
    if (InetPtonW(AF_INET, text, &a.Ipv4.sin_addr) == 1) {
        a.si_family = AF_INET;
    } else if (InetPtonW(AF_INET6, text, &a.Ipv6.sin6_addr) == 1) {
        a.si_family = AF_INET6;
    }
    return a;
}

MIB_IPFORWARD_ROW2 Route(NET_LUID luid, const wchar_t* prefix, UINT8 length, const wchar_t* nextHop, ULONG metric)
{
    IP_ADDRESS_PREFIX p{};
    p.Prefix = Addr(prefix);
    p.PrefixLength = length;
    SOCKADDR_INET hop{};
    if (nextHop) {
        hop = Addr(nextHop);
    }
    return MakeRoute(luid, p, hop, metric);
}

// Типичная система: Wi-Fi с 0/0 через домашний роутер.
NetworkSnapshot WifiOnly()
{
    NetworkSnapshot s;
    s.routes.push_back(Route(kWifi, L"0.0.0.0", 0, L"192.0.2.1", 0));
    s.interfaces.push_back({kWifi, AF_INET, 35, true});
    s.interfaces.push_back({kWifi, AF_INET6, 35, true});
    return s;
}

void AddHapp(NetworkSnapshot& s)
{
    s.routes.push_back(Route(kHapp, L"0.0.0.0", 0, nullptr, 0));
    s.interfaces.push_back({kHapp, AF_INET, 5, false});
}

void AddOpenVpn(NetworkSnapshot& s)
{
    s.routes.push_back(Route(kOpenVpn, L"0.0.0.0", 1, L"10.8.0.1", 0));
    s.routes.push_back(Route(kOpenVpn, L"128.0.0.0", 1, L"10.8.0.1", 0));
    s.routes.push_back(Route(kOpenVpn, L"10.8.0.0", 24, nullptr, 0));
    s.interfaces.push_back({kOpenVpn, AF_INET, 25, true});
}

RoutePolicy Policy(NET_LUID primary, std::vector<NET_LUID> ensure = {})
{
    RoutePolicy p;
    p.primary = primary;
    p.ensureDefault = std::move(ensure);
    return p;
}

// Применить план к снимку так, как это сделал бы Apply() с системой.
void Simulate(NetworkSnapshot& s, const RoutePlan& plan)
{
    for (const auto& c : plan.changes) {
        switch (c.kind) {
        case ChangeKind::DeleteRoute:
            std::erase_if(s.routes, [&](const MIB_IPFORWARD_ROW2& r) { return SameRouteKey(r, c.route); });
            break;
        case ChangeKind::AddRoute:
            s.routes.push_back(c.route);
            break;
        case ChangeKind::SetInterfaceMetric:
            for (auto& i : s.interfaces) {
                if (SameLuid(i.luid, c.luid) && i.family == c.family) {
                    i.metric = c.newMetric;
                    i.automatic = false;
                }
            }
            break;
        }
    }
}

size_t Count(const RoutePlan& plan, ChangeKind kind)
{
    return static_cast<size_t>(std::count_if(plan.changes.begin(), plan.changes.end(),
                                             [&](const RouteChange& c) { return c.kind == kind; }));
}

const RouteChange* FindChange(const RoutePlan& plan, ChangeKind kind, NET_LUID luid)
{
    for (const auto& c : plan.changes) {
        const NET_LUID target = c.kind == ChangeKind::SetInterfaceMetric ? c.luid : c.route.InterfaceLuid;
        if (c.kind == kind && SameLuid(target, luid)) {
            return &c;
        }
    }
    return nullptr;
}

// Лучший маршрут в интернет (0/0 или /1) по итоговой метрике: длинный префикс важнее.
NET_LUID Winner(const NetworkSnapshot& s, ADDRESS_FAMILY family)
{
    const MIB_IPFORWARD_ROW2* best = nullptr;
    for (const auto& r : s.routes) {
        if (r.DestinationPrefix.Prefix.si_family != family || !IsDefaultLikeRoute(r)) {
            continue;
        }
        if (!best || r.DestinationPrefix.PrefixLength > best->DestinationPrefix.PrefixLength ||
            (r.DestinationPrefix.PrefixLength == best->DestinationPrefix.PrefixLength &&
             s.EffectiveMetric(r) < s.EffectiveMetric(*best))) {
            best = &r;
        }
    }
    return best ? best->InterfaceLuid : NET_LUID{};
}

} // namespace

TEST(RoutesNothingToDo)
{
    const auto plan = RouteManager(Policy(kWifi)).Plan(WifiOnly());
    CHECK(plan.changes.empty());
    CHECK(plan.warnings.empty());   // нет IPv6-маршрутов вообще — предупреждать не о чем
}

TEST(RoutesVpnWithLowMetricLoses)
{
    auto s = WifiOnly();
    AddHapp(s);
    CHECK(SameLuid(Winner(s, AF_INET), kHapp));   // до: VPN забрал маршрут по умолчанию

    const RouteManager manager(Policy(kWifi));
    const auto plan = manager.Plan(s);
    CHECK(plan.changes.size() == 1);
    const auto* metric = FindChange(plan, ChangeKind::SetInterfaceMetric, kHapp);
    CHECK(metric && metric->oldMetric == 5 && !metric->oldAutomatic && metric->newMetric == 5000);

    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET), kWifi));   // после: основной снова Wi-Fi
    CHECK(manager.Plan(s).changes.empty());       // идемпотентность
}

TEST(RoutesOpenVpnSplitReplaced)
{
    auto s = WifiOnly();
    AddOpenVpn(s);
    CHECK(SameLuid(Winner(s, AF_INET), kOpenVpn));

    const RouteManager manager(Policy(kWifi));
    const auto plan = manager.Plan(s);
    CHECK(Count(plan, ChangeKind::DeleteRoute) == 2);   // 0/1 и 128/1, подсеть туннеля не трогаем
    CHECK(Count(plan, ChangeKind::AddRoute) == 1);
    const auto* add = FindChange(plan, ChangeKind::AddRoute, kOpenVpn);
    CHECK(add && add->route.DestinationPrefix.PrefixLength == 0);
    CHECK(add && SameAddress(add->route.NextHop, Addr(L"10.8.0.1")));   // шлюз туннеля сохранён
    CHECK(FindChange(plan, ChangeKind::SetInterfaceMetric, kOpenVpn) != nullptr);

    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET), kWifi));
    CHECK(manager.Plan(s).changes.empty());
}

TEST(RoutesSeveralVpns)
{
    auto s = WifiOnly();
    AddOpenVpn(s);
    AddHapp(s);
    const RouteManager manager(Policy(kWifi));
    const auto plan = manager.Plan(s);
    CHECK(FindChange(plan, ChangeKind::SetInterfaceMetric, kHapp) != nullptr);
    CHECK(FindChange(plan, ChangeKind::SetInterfaceMetric, kOpenVpn) != nullptr);
    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET), kWifi));
    CHECK(manager.Plan(s).changes.empty());
}

TEST(RoutesEnsureDefault)
{
    auto s = WifiOnly();
    // VPN без маршрута по умолчанию (только своя подсеть) — к нему хотят привязывать приложения
    s.routes.push_back(Route(kOpenVpn, L"10.8.0.0", 24, nullptr, 0));
    s.routes.push_back(Route(kOpenVpn, L"198.51.100.0", 24, L"10.8.0.1", 0));
    s.interfaces.push_back({kOpenVpn, AF_INET, 25, true});

    const RouteManager manager(Policy(kWifi, {kOpenVpn}));
    const auto plan = manager.Plan(s);
    const auto* add = FindChange(plan, ChangeKind::AddRoute, kOpenVpn);
    CHECK(add && add->route.DestinationPrefix.PrefixLength == 0);
    CHECK(add && SameAddress(add->route.NextHop, Addr(L"10.8.0.1")));   // шлюз взят из маршрута интерфейса
    CHECK(FindChange(plan, ChangeKind::SetInterfaceMetric, kOpenVpn) != nullptr);

    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET), kWifi));   // добавленный 0/0 проигрывает основному
    CHECK(manager.Plan(s).changes.empty());
}

TEST(RoutesEnsureDefaultOnLink)
{
    auto s = WifiOnly();
    s.interfaces.push_back({kHapp, AF_INET, 5, false});   // TUN без маршрутов с шлюзом
    const auto plan = RouteManager(Policy(kWifi, {kHapp})).Plan(s);
    const auto* add = FindChange(plan, ChangeKind::AddRoute, kHapp);
    CHECK(add && IsZeroAddress(add->route.NextHop));   // on-link
}

TEST(RoutesEnsureDefaultMissingInterface)
{
    const auto plan = RouteManager(Policy(kWifi, {kHapp})).Plan(WifiOnly());
    CHECK(plan.changes.empty());
    CHECK(plan.warnings.size() == 1);   // IPv4: интерфейс недоступен; для IPv6 молчим
}

TEST(RoutesPrimaryWithoutDefaultRoute)
{
    // Основной интерфейс без 0/0 — ничего не трогаем, иначе система останется без интернета
    NetworkSnapshot s;
    s.interfaces.push_back({kWifi, AF_INET, 35, true});
    AddHapp(s);
    const auto plan = RouteManager(Policy(kWifi)).Plan(s);
    CHECK(plan.changes.empty());
    CHECK(plan.warnings.size() == 1);
}

TEST(RoutesGlobalSwitchToSplitVpn)
{
    // Глобальный переключатель: основной — OpenVPN со своими 0/1 + 128/1. Его маршруты не
    // удаляются, а 0/0 Wi-Fi и так проигрывают по длине префикса.
    auto s = WifiOnly();
    AddOpenVpn(s);
    const auto plan = RouteManager(Policy(kOpenVpn)).Plan(s);
    CHECK(plan.changes.empty());
    CHECK(SameLuid(Winner(s, AF_INET), kOpenVpn));
}

TEST(RoutesGlobalSwitchToVpnWithDefault)
{
    // Основной — TUN-клиент, у которого 0/0 проигрывает Wi-Fi: понижаем приоритет Wi-Fi
    auto s = WifiOnly();
    s.routes.push_back(Route(kHapp, L"0.0.0.0", 0, nullptr, 0));
    s.interfaces.push_back({kHapp, AF_INET, 50, true});
    const RouteManager manager(Policy(kHapp));
    const auto plan = manager.Plan(s);
    const auto* metric = FindChange(plan, ChangeKind::SetInterfaceMetric, kWifi);
    CHECK(metric && metric->oldAutomatic && metric->newMetric == 5000);
    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET), kHapp));
    CHECK(manager.Plan(s).changes.empty());
}

TEST(RoutesSecondaryMetricAboveHighPrimary)
{
    // Если основной сам с огромной метрикой, вторичным ставится метрика выше него
    auto s = WifiOnly();
    s.interfaces[0].metric = 9000;
    AddHapp(s);
    const auto plan = RouteManager(Policy(kWifi)).Plan(s);
    const auto* metric = FindChange(plan, ChangeKind::SetInterfaceMetric, kHapp);
    CHECK(metric && metric->newMetric == 9100);
}

TEST(RoutesIpv6PlannedSeparately)
{
    auto s = WifiOnly();
    s.routes.push_back(Route(kWifi, L"::", 0, L"fe80::1", 0));
    s.routes.push_back(Route(kHapp, L"::", 0, nullptr, 0));
    s.interfaces.push_back({kHapp, AF_INET6, 5, false});
    const RouteManager manager(Policy(kWifi));
    const auto plan = manager.Plan(s);
    const auto* metric = FindChange(plan, ChangeKind::SetInterfaceMetric, kHapp);
    CHECK(metric && metric->family == AF_INET6);
    CHECK(plan.changes.size() == 1);   // в IPv4 у Happ нет 0/0 — менять нечего
    Simulate(s, plan);
    CHECK(SameLuid(Winner(s, AF_INET6), kWifi));
    CHECK(manager.Plan(s).changes.empty());
}

TEST(RoutesIpv6PrimaryWithoutDefaultWarns)
{
    // В IPv6 у VPN есть маршрут по умолчанию, а у основного нет — предупреждение, без изменений
    auto s = WifiOnly();
    s.routes.push_back(Route(kHapp, L"::", 0, nullptr, 0));
    s.interfaces.push_back({kHapp, AF_INET6, 5, false});
    const auto plan = RouteManager(Policy(kWifi)).Plan(s);
    CHECK(plan.changes.empty());
    CHECK(plan.warnings.size() == 1);
}

TEST(RoutesPlanIsDeterministic)
{
    auto s = WifiOnly();
    AddOpenVpn(s);
    AddHapp(s);
    const RouteManager manager(Policy(kWifi, {kOpenVpn}));
    const auto a = manager.Plan(s);
    const auto b = manager.Plan(s);
    CHECK(a.changes.size() == b.changes.size());
    for (size_t i = 0; i < a.changes.size() && i < b.changes.size(); ++i) {
        CHECK(a.changes[i].kind == b.changes[i].kind);
        CHECK(a.changes[i].description == b.changes[i].description);
    }
}
