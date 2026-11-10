#include "core/Routes.h"
#include "core/Util.h"

#include <system_error>

namespace approute {

std::vector<MIB_IPFORWARD_ROW2> GetRoutes(ADDRESS_FAMILY family)
{
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    const DWORD rc = GetIpForwardTable2(family, &table);
    if (rc != NO_ERROR) {
        throw std::system_error(static_cast<int>(rc), std::system_category(), "GetIpForwardTable2");
    }
    std::vector<MIB_IPFORWARD_ROW2> rows(table->Table, table->Table + table->NumEntries);
    FreeMibTable(table);
    return rows;
}

bool IsDefaultRoute(const MIB_IPFORWARD_ROW2& row)
{
    return row.DestinationPrefix.PrefixLength == 0;
}

bool IsSplitDefaultRoute(const MIB_IPFORWARD_ROW2& row)
{
    // 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1 — любой /1 покрывает половину адресного пространства
    return row.DestinationPrefix.PrefixLength == 1;
}

bool SameRouteKey(const MIB_IPFORWARD_ROW2& a, const MIB_IPFORWARD_ROW2& b)
{
    return SameLuid(a.InterfaceLuid, b.InterfaceLuid)
        && a.DestinationPrefix.PrefixLength == b.DestinationPrefix.PrefixLength
        && SameAddress(a.DestinationPrefix.Prefix, b.DestinationPrefix.Prefix)
        && SameAddress(a.NextHop, b.NextHop);
}

std::optional<MIB_IPINTERFACE_ROW> GetIpInterface(NET_LUID luid, ADDRESS_FAMILY family)
{
    MIB_IPINTERFACE_ROW row;
    InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) {
        return std::nullopt;
    }
    return row;
}

std::optional<ULONG> GetInterfaceMetric(NET_LUID luid, ADDRESS_FAMILY family)
{
    if (auto row = GetIpInterface(luid, family)) {
        return row->Metric;
    }
    return std::nullopt;
}

ULONG64 EffectiveMetric(const MIB_IPFORWARD_ROW2& row)
{
    const auto ifMetric = GetInterfaceMetric(row.InterfaceLuid, row.DestinationPrefix.Prefix.si_family);
    return static_cast<ULONG64>(row.Metric) + ifMetric.value_or(0);
}

MIB_IPFORWARD_ROW2 MakeRoute(NET_LUID luid, const IP_ADDRESS_PREFIX& destination,
                             const SOCKADDR_INET& nextHop, ULONG metric)
{
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid;
    row.DestinationPrefix = destination;
    row.NextHop = nextHop;
    row.NextHop.si_family = destination.Prefix.si_family;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    return row;
}

std::optional<MIB_IPFORWARD_ROW2> BestRouteTo(const SOCKADDR_INET& destination)
{
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    if (GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source) != NO_ERROR) {
        return std::nullopt;
    }
    return route;
}

} // namespace approute
