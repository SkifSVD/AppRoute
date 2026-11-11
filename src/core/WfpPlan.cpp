// Определения GUID из AppRouteWfpShared.h — в этой единице трансляции
#include <initguid.h>

#include "core/WfpPlan.h"

#include "core/Util.h"

#include <cstring>

namespace approute {

namespace {

bool IsFullPath(const std::wstring& path)
{
    return path.size() > 2 && ((path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) || path.starts_with(L"\\\\"));
}

std::wstring ExpandPath(const std::wstring& path)
{
    wchar_t out[MAX_PATH * 2] = {};
    const DWORD n = ExpandEnvironmentStringsW(path.c_str(), out, static_cast<DWORD>(std::size(out)));
    return n > 0 && n <= std::size(out) ? std::wstring(out) : path;
}

WfpExemption Prefix(ADDRESS_FAMILY family, const char* text, UINT8 length)
{
    WfpExemption e;
    e.prefix.si_family = family;
    if (family == AF_INET) {
        InetPtonA(AF_INET, text, &e.prefix.Ipv4.sin_addr);
    } else {
        InetPtonA(AF_INET6, text, &e.prefix.Ipv6.sin6_addr);
    }
    e.length = length;
    return e;
}

// Обнулить биты адреса за пределами префикса
WfpExemption Network(const SOCKADDR_INET& address, UINT8 length)
{
    WfpExemption e;
    e.prefix.si_family = address.si_family;
    e.length = length;
    unsigned char* bytes = nullptr;
    unsigned size = 0;
    if (address.si_family == AF_INET) {
        e.prefix.Ipv4.sin_addr = address.Ipv4.sin_addr;
        bytes = reinterpret_cast<unsigned char*>(&e.prefix.Ipv4.sin_addr);
        size = 4;
    } else {
        e.prefix.Ipv6.sin6_addr = address.Ipv6.sin6_addr;
        bytes = reinterpret_cast<unsigned char*>(&e.prefix.Ipv6.sin6_addr);
        size = 16;
    }
    for (unsigned i = 0; i < size; ++i) {
        const unsigned bit = i * 8;
        if (bit >= length) {
            bytes[i] = 0;
        } else if (bit + 8 > length) {
            bytes[i] &= static_cast<unsigned char>(0xFFu << (8 - (length - bit)));
        }
    }
    return e;
}

bool SameExemption(const WfpExemption& a, const WfpExemption& b)
{
    if (a.length != b.length || a.prefix.si_family != b.prefix.si_family) {
        return false;
    }
    return a.prefix.si_family == AF_INET
               ? a.prefix.Ipv4.sin_addr.s_addr == b.prefix.Ipv4.sin_addr.s_addr
               : std::memcmp(&a.prefix.Ipv6.sin6_addr, &b.prefix.Ipv6.sin6_addr, 16) == 0;
}

} // namespace

APPROUTE_TARGET MakeWfpTarget(const NetAdapter* a, const Rule& rule)
{
    APPROUTE_TARGET t{};
    t.version = APPROUTE_TARGET_VERSION;
    const bool defaultV4 = rule.onUnavailable == OnUnavailable::Default;
    const bool defaultV6 = rule.ipv6 == Ipv6Mode::Follow ? defaultV4 : rule.ipv6 == Ipv6Mode::Default;
    if (defaultV4) {
        t.flags |= APPROUTE_TARGET_DEFAULT_V4;
    }
    if (defaultV6) {
        t.flags |= APPROUTE_TARGET_DEFAULT_V6;
    }
    if (!a) {
        return t;
    }
    t.luid = a->luid.Value;
    if (!a->IsUp()) {
        return t;   // отключён — адресов нет, действует политика
    }
    for (const UnicastAddress& u : a->unicast) {
        if (u.address.si_family == AF_INET && !(t.flags & APPROUTE_TARGET_HAS_V4)) {
            const auto* b = reinterpret_cast<const unsigned char*>(&u.address.Ipv4.sin_addr);
            if (b[0] == 169 && b[1] == 254) {
                continue;   // автоматический адрес без DHCP — выхода в сеть через него нет
            }
            std::memcpy(t.v4, b, 4);
            t.flags |= APPROUTE_TARGET_HAS_V4;
        } else if (u.address.si_family == AF_INET6 && !(t.flags & APPROUTE_TARGET_HAS_V6) &&
                   !IN6_IS_ADDR_LINKLOCAL(&u.address.Ipv6.sin6_addr)) {
            std::memcpy(t.v6, &u.address.Ipv6.sin6_addr, 16);
            t.v6ScopeId = u.address.Ipv6.sin6_scope_id;
            t.flags |= APPROUTE_TARGET_HAS_V6;
        }
    }
    return t;
}

bool SameWfpTarget(const APPROUTE_TARGET& a, const APPROUTE_TARGET& b)
{
    return a.version == b.version && a.flags == b.flags && a.luid == b.luid && std::memcmp(a.v4, b.v4, 4) == 0 &&
           std::memcmp(a.v6, b.v6, 16) == 0 && a.v6ScopeId == b.v6ScopeId;
}

bool SameWfpPlan(const WfpPlan& a, const WfpPlan& b)
{
    if (!EqualsIgnoreCase(a.userSid, b.userSid) || a.filters.size() != b.filters.size() ||
        a.exemptions.size() != b.exemptions.size()) {
        return false;
    }
    for (size_t i = 0; i < a.filters.size(); ++i) {
        if (!EqualsIgnoreCase(a.filters[i].appPath, b.filters[i].appPath) ||
            !SameWfpTarget(a.filters[i].target, b.filters[i].target)) {
            return false;
        }
    }
    for (size_t i = 0; i < a.exemptions.size(); ++i) {
        const WfpExemption& x = a.exemptions[i];
        const WfpExemption& y = b.exemptions[i];
        if (x.length != y.length || x.prefix.si_family != y.prefix.si_family) {
            return false;
        }
        const bool same = x.prefix.si_family == AF_INET
                              ? x.prefix.Ipv4.sin_addr.s_addr == y.prefix.Ipv4.sin_addr.s_addr
                              : std::memcmp(&x.prefix.Ipv6.sin6_addr, &y.prefix.Ipv6.sin6_addr, 16) == 0;
        if (!same) {
            return false;
        }
    }
    return true;
}

WfpPlan WfpPlanFromConfig(const Config& config, const std::vector<NetAdapter>& adapters, const std::wstring& userSid,
                          const WfpPackageResolver& resolvePackage)
{
    WfpPlan plan;
    plan.userSid = userSid;

    for (const Rule& rule : config.rules) {
        if (!rule.proxy.empty()) {
            plan.notes.push_back(rule.app + L": правило «прокси» действует только для программ, запущенных через AppRoute");
            continue;
        }
        if (IsPackageApp(rule.app)) {
            std::wstring error = L"приложение из пакета не найдено";
            const auto exes = resolvePackage ? resolvePackage(rule.app, &error) : std::nullopt;
            if (!exes) {
                plan.notes.push_back(rule.app + L": " + error);
                continue;
            }
            std::vector<std::wstring> paths = {exes->main};
            if (rule.includeChildren) {
                paths.insert(paths.end(), exes->helpers.begin(), exes->helpers.end());
            }
            for (const std::wstring& path : paths) {
                WfpAppFilter f;
                f.app = rule.app;
                f.appPath = path;
                f.adapter = rule.adapter;
                f.target = MakeWfpTarget(FindAdapter(adapters, rule.adapter), rule);
                plan.filters.push_back(std::move(f));
            }
            continue;
        }
        const std::wstring path = ExpandPath(rule.app);
        if (!IsFullPath(path)) {
            plan.notes.push_back(rule.app + L": для программ, запущенных любым способом, нужен полный путь к программе");
            continue;
        }
        WfpAppFilter f;
        f.app = rule.app;
        f.appPath = path;
        f.adapter = rule.adapter;
        f.target = MakeWfpTarget(FindAdapter(adapters, rule.adapter), rule);
        plan.filters.push_back(std::move(f));
    }

    // Напрямую: loopback, link-local, multicast, широковещание и подсети интерфейсов (локальная
    // сеть, принтеры) — как в hook-DLL
    plan.exemptions = {
        Prefix(AF_INET, "127.0.0.0", 8),    Prefix(AF_INET, "169.254.0.0", 16), Prefix(AF_INET, "224.0.0.0", 4),
        Prefix(AF_INET, "255.255.255.255", 32), Prefix(AF_INET6, "::1", 128), Prefix(AF_INET6, "fe80::", 10),
        Prefix(AF_INET6, "ff00::", 8),
    };
    for (const NetAdapter& a : adapters) {
        if (!a.IsUp()) {
            continue;
        }
        for (const UnicastAddress& u : a.unicast) {
            const UINT8 max = u.address.si_family == AF_INET ? 32 : 128;
            if (u.prefixLength == 0 || u.prefixLength >= max) {
                continue;   // /32 и /128 — сам адрес, не подсеть
            }
            if (u.address.si_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&u.address.Ipv6.sin6_addr)) {
                continue;
            }
            const WfpExemption e = Network(u.address, u.prefixLength);
            bool known = false;
            for (const WfpExemption& x : plan.exemptions) {
                known = known || SameExemption(x, e);
            }
            if (!known) {
                plan.exemptions.push_back(e);
            }
        }
    }
    return plan;
}

} // namespace approute
