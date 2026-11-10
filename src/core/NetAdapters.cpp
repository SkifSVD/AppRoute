#include "core/NetAdapters.h"
#include "core/Util.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <system_error>

namespace approute {

namespace {

SOCKADDR_INET ToSockaddrInet(const SOCKET_ADDRESS& sa)
{
    SOCKADDR_INET out{};
    if (sa.lpSockaddr && sa.iSockaddrLength > 0) {
        const size_t len = std::min(static_cast<size_t>(sa.iSockaddrLength), sizeof(out));
        std::memcpy(&out, sa.lpSockaddr, len);
    }
    return out;
}

bool IsAllDigits(std::wstring_view s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), [](wchar_t c) { return std::iswdigit(c); });
}

} // namespace

std::vector<NetAdapter> EnumerateAdapters()
{
    constexpr ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;

    ULONG size = 32 * 1024;
    std::vector<std::byte> buffer;
    DWORD rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (rc == ERROR_NO_DATA) {
        return {};
    }
    if (rc != NO_ERROR) {
        throw std::system_error(static_cast<int>(rc), std::system_category(), "GetAdaptersAddresses");
    }

    std::vector<NetAdapter> result;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        NetAdapter n;
        n.luid = a->Luid;
        n.ifIndex = a->IfIndex;
        n.ipv6IfIndex = a->Ipv6IfIndex;
        ConvertInterfaceLuidToGuid(&a->Luid, &n.guid);
        n.alias = a->FriendlyName ? a->FriendlyName : L"";
        n.description = a->Description ? a->Description : L"";
        n.ifType = a->IfType;
        n.operStatus = a->OperStatus;
        n.ipv4Metric = a->Ipv4Metric;
        n.ipv6Metric = a->Ipv6Metric;

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            n.unicast.push_back({ToSockaddrInet(u->Address), u->OnLinkPrefixLength});
        }
        for (auto* g = a->FirstGatewayAddress; g; g = g->Next) {
            n.gateways.push_back(ToSockaddrInet(g->Address));
        }
        for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
            n.dnsServers.push_back(ToSockaddrInet(d->Address));
        }

        MIB_IF_ROW2 row{};
        row.InterfaceLuid = a->Luid;
        if (GetIfEntry2(&row) == NO_ERROR) {
            n.hardware = row.InterfaceAndOperStatusFlags.HardwareInterface != FALSE;
        }

        result.push_back(std::move(n));
    }
    return result;
}

const NetAdapter* FindAdapter(const std::vector<NetAdapter>& adapters, std::wstring_view key)
{
    if (IsAllDigits(key)) {
        const auto index = static_cast<NET_IFINDEX>(std::wcstoul(std::wstring(key).c_str(), nullptr, 10));
        for (const auto& a : adapters) {
            if (a.ifIndex == index || a.ipv6IfIndex == index) {
                return &a;
            }
        }
        return nullptr;
    }
    for (const auto& a : adapters) {
        if (EqualsIgnoreCase(GuidToString(a.guid), key) || EqualsIgnoreCase(a.alias, key)) {
            return &a;
        }
    }
    return nullptr;
}

const NetAdapter* FindAdapter(const std::vector<NetAdapter>& adapters, NET_LUID luid)
{
    for (const auto& a : adapters) {
        if (SameLuid(a.luid, luid)) {
            return &a;
        }
    }
    return nullptr;
}

} // namespace approute
