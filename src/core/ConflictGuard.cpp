#include "core/ConflictGuard.h"

#include "core/Util.h"

#include <algorithm>
#include <format>

namespace approute {

namespace {

const wchar_t* FamilyName(ADDRESS_FAMILY family)
{
    return family == AF_INET ? L"IPv4" : L"IPv6";
}

NET_LUID ObjectLuid(const RouteChange& c)
{
    return c.kind == ChangeKind::SetInterfaceMetric ? c.luid : c.route.InterfaceLuid;
}

std::wstring ObjectName(const RouteChange& c)
{
    if (c.kind == ChangeKind::SetInterfaceMetric) {
        return std::format(L"{}-метрика интерфейса [{}]", FamilyName(c.family), InterfaceName(c.luid));
    }
    return std::format(L"маршрут {} интерфейса [{}]", FormatPrefix(c.route.DestinationPrefix),
                       InterfaceName(c.route.InterfaceLuid));
}

} // namespace

std::wstring ConflictGuard::Key(const RouteChange& c)
{
    if (c.kind == ChangeKind::SetInterfaceMetric) {
        return std::format(L"metric {:016x} {}", c.luid.Value, static_cast<int>(c.family));
    }
    // Удаление и добавление одного маршрута — один объект: «бой» может идти и так
    return std::format(L"route {:016x} {} {}", ObjectLuid(c).Value, FormatPrefix(c.route.DestinationPrefix),
                       FormatAddress(c.route.NextHop));
}

bool ConflictGuard::InCooldown(const RouteChange& change, ULONGLONG now) const
{
    const auto it = objects_.find(Key(change));
    return it != objects_.end() && it->second.blockedUntil > now;
}

std::vector<RouteChange> ConflictGuard::Filter(const std::vector<RouteChange>& changes, ULONGLONG now,
                                               std::vector<std::wstring>& messages)
{
    std::vector<RouteChange> allowed;
    for (const auto& change : changes) {
        State& state = objects_[Key(change)];
        if (state.blockedUntil > now) {
            continue;   // пауза: предупреждение уже было
        }
        if (state.blockedUntil != 0) {
            // Пауза закончилась — пробуем снова, счёт с нуля
            state.blockedUntil = 0;
            state.fixes.clear();
            messages.push_back(std::format(L"пауза закончилась, снова исправляю: {}", ObjectName(change)));
        }

        std::erase_if(state.fixes, [&](ULONGLONG t) { return now - t > settings_.windowMs; });
        if (state.fixes.size() >= settings_.maxFixes) {
            state.blockedUntil = now + settings_.cooldownMs;
            state.fixes.clear();
            messages.push_back(std::format(
                L"конфликт: {} возвращается после каждого исправления ({} раз за {} с) — похоже, "
                L"VPN-клиент сам следит за ней. Перестаю исправлять на {} мин; чтобы конфликта не было, "
                L"настройте метрику в самом клиенте или выберите другой основной интерфейс (--primary)",
                ObjectName(change), settings_.maxFixes, settings_.windowMs / 1000,
                settings_.cooldownMs / 60'000));
            continue;
        }
        state.fixes.push_back(now);
        allowed.push_back(change);
    }
    return allowed;
}

} // namespace approute
