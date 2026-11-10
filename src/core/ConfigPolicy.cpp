#include "core/ConfigPolicy.h"

#include "core/Util.h"

#include <algorithm>
#include <format>

namespace approute {

namespace {

bool Contains(const std::vector<NET_LUID>& list, NET_LUID luid)
{
    return std::any_of(list.begin(), list.end(), [&](NET_LUID l) { return SameLuid(l, luid); });
}

bool SamePrefix(const IP_ADDRESS_PREFIX& a, const IP_ADDRESS_PREFIX& b)
{
    return a.PrefixLength == b.PrefixLength && SameAddress(a.Prefix, b.Prefix);
}

} // namespace

ConfigPolicy PolicyFromConfig(const Config& config, const std::vector<NetAdapter>& adapters,
                              std::optional<NET_LUID> detected, const std::vector<NET_LUID>& internetRoutes)
{
    ConfigPolicy out;
    out.primary = ChoosePrimary(config.primary, adapters, detected, internetRoutes);
    if (!out.primary.note.empty()) {
        out.notes.push_back(out.primary.note);
    }
    if (!out.primary.luid) {
        return out;
    }
    RoutePolicy policy;
    policy.primary = *out.primary.luid;

    // Интерфейсы правил: без маршрута по умолчанию привязанный к ним сокет никуда не уйдёт
    for (const Rule& rule : config.rules) {
        const NetAdapter* a = FindAdapter(adapters, rule.adapter);
        if (!a || SameLuid(a->luid, policy.primary) || Contains(policy.ensureDefault, a->luid)) {
            continue;   // интерфейса сейчас нет (VPN выключен) — появится, политика пересчитается
        }
        policy.ensureDefault.push_back(a->luid);
    }

    for (const ConfigRoute& route : config.routes) {
        const auto prefix = ParsePrefix(route.prefix);
        const NetAdapter* a = FindAdapter(adapters, route.adapter);
        if (!prefix) {
            continue;   // проверено при чтении конфига
        }
        if (!a) {
            const KnownAdapter* known = FindKnownAdapter(config, route.adapter);
            out.notes.push_back(std::format(L"подсеть {} не закреплена: интерфейса «{}» сейчас нет", route.prefix,
                                            known && !known->name.empty() ? known->name : route.adapter));
            continue;
        }
        policy.pinned.push_back({*prefix, a->luid});
    }
    out.policy = std::move(policy);
    return out;
}

ConfigPolicy PolicyFromConfig(const Config& config)
{
    return PolicyFromConfig(config, EnumerateAdapters(), DetectPrimaryInterface(), InterfacesWithInternetRoute());
}

bool SamePolicy(const RoutePolicy& a, const RoutePolicy& b)
{
    if (!SameLuid(a.primary, b.primary) || a.secondaryMetric != b.secondaryMetric ||
        a.ensureDefault.size() != b.ensureDefault.size() || a.pinned.size() != b.pinned.size()) {
        return false;
    }
    for (const NET_LUID l : a.ensureDefault) {
        if (!Contains(b.ensureDefault, l)) {
            return false;
        }
    }
    for (const PinnedRoute& p : a.pinned) {
        const bool found = std::any_of(b.pinned.begin(), b.pinned.end(), [&](const PinnedRoute& q) {
            return SameLuid(p.luid, q.luid) && SamePrefix(p.prefix, q.prefix);
        });
        if (!found) {
            return false;
        }
    }
    return true;
}

} // namespace approute
