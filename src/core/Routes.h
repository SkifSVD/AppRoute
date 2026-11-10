#pragma once

#include "core/Win.h"

#include <optional>
#include <vector>

namespace approute {

// Тонкая обёртка над IP Helper API для таблицы маршрутов (только активное хранилище:
// всё, что меняется через эти функции, исчезает после перезагрузки).

std::vector<MIB_IPFORWARD_ROW2> GetRoutes(ADDRESS_FAMILY family);

// 0.0.0.0/0 или ::/0
bool IsDefaultRoute(const MIB_IPFORWARD_ROW2& row);

// "Расщеплённый" маршрут по умолчанию: 0.0.0.0/1 + 128.0.0.0/1 (OpenVPN redirect-gateway def1
// и многие другие VPN), а в IPv6 ещё 2000::/3 и 2000::/4 + 3000::/4 (весь глобальный интернет).
// Он перекрывает /0 за счёт более длинного префикса, а не метрики.
bool IsSplitDefaultRoute(const MIB_IPFORWARD_ROW2& row);

inline bool IsDefaultLikeRoute(const MIB_IPFORWARD_ROW2& row)
{
    return IsDefaultRoute(row) || IsSplitDefaultRoute(row);
}

// Совпадение ключа маршрута: интерфейс + префикс + шлюз.
bool SameRouteKey(const MIB_IPFORWARD_ROW2& a, const MIB_IPFORWARD_ROW2& b);

std::optional<MIB_IPINTERFACE_ROW> GetIpInterface(NET_LUID luid, ADDRESS_FAMILY family);

// Метрика интерфейса для семейства адресов; nullopt, если интерфейса нет.
std::optional<ULONG> GetInterfaceMetric(NET_LUID luid, ADDRESS_FAMILY family);

// Итоговая метрика маршрута, по которой Windows выбирает путь: метрика маршрута + интерфейса.
ULONG64 EffectiveMetric(const MIB_IPFORWARD_ROW2& row);

// Новая строка маршрута с разумными значениями по умолчанию.
MIB_IPFORWARD_ROW2 MakeRoute(NET_LUID luid, const IP_ADDRESS_PREFIX& destination,
                             const SOCKADDR_INET& nextHop, ULONG metric);

// Маршрут, который Windows выберет для указанного адреса (без привязки к интерфейсу).
std::optional<MIB_IPFORWARD_ROW2> BestRouteTo(const SOCKADDR_INET& destination);

} // namespace approute
