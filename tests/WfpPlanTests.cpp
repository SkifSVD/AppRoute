// Тесты описания объектов WFP для драйвера (issue #18).

#include "core/WfpPlan.h"
#include "core/Util.h"

#include "Test.h"

#include <objbase.h>

#include <cstring>

using namespace approute;

namespace {

constexpr wchar_t kVpn[] = L"{33333333-0000-0000-0000-000000000001}";
constexpr wchar_t kWifi[] = L"{33333333-0000-0000-0000-000000000002}";

UnicastAddress V4(const char* text, UINT8 prefix)
{
    UnicastAddress u;
    u.address.si_family = AF_INET;
    InetPtonA(AF_INET, text, &u.address.Ipv4.sin_addr);
    u.prefixLength = prefix;
    return u;
}

UnicastAddress V6(const char* text, UINT8 prefix)
{
    UnicastAddress u;
    u.address.si_family = AF_INET6;
    InetPtonA(AF_INET6, text, &u.address.Ipv6.sin6_addr);
    u.prefixLength = prefix;
    return u;
}

NetAdapter Adapter(ULONG64 luid, const wchar_t* guid, std::vector<UnicastAddress> unicast, bool up = true)
{
    NetAdapter a;
    a.luid.Value = luid;
    CLSIDFromString(guid, &a.guid);
    a.operStatus = up ? IfOperStatusUp : IfOperStatusDown;
    a.unicast = std::move(unicast);
    return a;
}

Rule MakeRule(const wchar_t* app, const wchar_t* adapter)
{
    Rule r;
    r.app = app;
    r.adapter = adapter;
    return r;
}

bool HasExemption(const WfpPlan& plan, const char* text, UINT8 length)
{
    SOCKADDR_INET want{};
    const bool v6 = std::strchr(text, ':') != nullptr;
    want.si_family = v6 ? AF_INET6 : AF_INET;
    InetPtonA(want.si_family, text, v6 ? static_cast<void*>(&want.Ipv6.sin6_addr) : static_cast<void*>(&want.Ipv4.sin_addr));
    for (const auto& e : plan.exemptions) {
        if (e.length == length && e.prefix.si_family == want.si_family &&
            (v6 ? std::memcmp(&e.prefix.Ipv6.sin6_addr, &want.Ipv6.sin6_addr, 16) == 0
                : e.prefix.Ipv4.sin_addr.s_addr == want.Ipv4.sin_addr.s_addr)) {
            return true;
        }
    }
    return false;
}

} // namespace

TEST(WfpPlanFiltersAndNotes)
{
    Config c;
    c.rules = {MakeRule(L"C:\\Apps\\tg.exe", kVpn), MakeRule(L"%SystemRoot%\\System32\\curl.exe", kWifi),
               MakeRule(L"chrome.exe", kVpn)};
    Rule proxy;
    proxy.app = L"C:\\Apps\\p.exe";
    proxy.proxy = L"127.0.0.1:10808";
    c.rules.push_back(proxy);

    const std::vector<NetAdapter> adapters = {
        Adapter(7, kVpn, {V4("10.8.0.6", 24), V6("fe80::1", 64), V6("fd00::6", 64)}),
        Adapter(9, kWifi, {V4("169.254.3.4", 16)}),
    };
    const WfpPlan plan = WfpPlanFromConfig(c, adapters, L"S-1-5-21-1-2-3-1001");
    CHECK(plan.userSid == L"S-1-5-21-1-2-3-1001");
    CHECK(plan.filters.size() == 2);        // имя без пути и прокси — в пояснениях
    CHECK(plan.notes.size() == 2);
    if (plan.filters.size() == 2) {
        const APPROUTE_TARGET& vpn = plan.filters[0].target;
        CHECK(vpn.version == APPROUTE_TARGET_VERSION && vpn.luid == 7);
        CHECK((vpn.flags & APPROUTE_TARGET_HAS_V4) && (vpn.flags & APPROUTE_TARGET_HAS_V6));
        CHECK(vpn.v4[0] == 10 && vpn.v4[3] == 6);
        CHECK(vpn.v6[0] == 0xFD);            // не link-local
        CHECK(!(vpn.flags & (APPROUTE_TARGET_DEFAULT_V4 | APPROUTE_TARGET_DEFAULT_V6)));   // block

        // %SystemRoot% раскрыт; 169.254 — не адрес для выхода
        CHECK(plan.filters[1].appPath.find(L'%') == std::wstring::npos);
        CHECK(!(plan.filters[1].target.flags & APPROUTE_TARGET_HAS_V4));
    }
    CHECK(HasExemption(plan, "127.0.0.0", 8));
    CHECK(HasExemption(plan, "10.8.0.0", 24));    // подсеть интерфейса — напрямую
    CHECK(HasExemption(plan, "fd00::", 64));
    CHECK(HasExemption(plan, "169.254.0.0", 16));
}

TEST(WfpTargetPolicy)
{
    Rule r = MakeRule(L"C:\\a.exe", kVpn);
    r.onUnavailable = OnUnavailable::Default;
    APPROUTE_TARGET t = MakeWfpTarget(nullptr, r);
    CHECK(t.flags == (APPROUTE_TARGET_DEFAULT_V4 | APPROUTE_TARGET_DEFAULT_V6));   // ipv6 follow

    r.ipv6 = Ipv6Mode::Block;
    t = MakeWfpTarget(nullptr, r);
    CHECK(t.flags == APPROUTE_TARGET_DEFAULT_V4);

    // Отключённый интерфейс — адресов нет, даже если они остались в списке
    const NetAdapter down = Adapter(5, kVpn, {V4("10.1.1.1", 24)}, false);
    t = MakeWfpTarget(&down, MakeRule(L"C:\\a.exe", kVpn));
    CHECK(t.luid == 5 && !(t.flags & APPROUTE_TARGET_HAS_V4));

    const NetAdapter up = Adapter(5, kVpn, {V4("10.1.1.1", 24)});
    const APPROUTE_TARGET a = MakeWfpTarget(&up, MakeRule(L"C:\\a.exe", kVpn));
    APPROUTE_TARGET b = a;
    CHECK(SameWfpTarget(a, b));
    b.v4[3] = 2;   // DHCP выдал другой адрес — контекст нужно обновить
    CHECK(!SameWfpTarget(a, b));
}
