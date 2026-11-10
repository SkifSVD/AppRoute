#pragma once

#include "core/Win.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

struct UnicastAddress {
    SOCKADDR_INET address{};
    UINT8 prefixLength = 0;
};

// Сетевой адаптер так, как его видит Windows (GetAdaptersAddresses + GetIfEntry2).
// Правила AppRoute ссылаются на адаптер по GUID: он стабилен, в отличие от IP и ifIndex.
struct NetAdapter {
    NET_LUID luid{};
    NET_IFINDEX ifIndex = 0;      // индекс IPv4
    NET_IFINDEX ipv6IfIndex = 0;
    GUID guid{};
    std::wstring alias;           // "Беспроводная сеть", "happ-xray"
    std::wstring description;     // "Intel(R) Wi-Fi 7 BE200 320MHz"
    IFTYPE ifType = 0;
    IF_OPER_STATUS operStatus = IfOperStatusDown;
    bool hardware = false;        // физическое устройство (не TAP/TUN/Hyper-V)
    ULONG ipv4Metric = 0;
    ULONG ipv6Metric = 0;
    std::vector<UnicastAddress> unicast;
    std::vector<SOCKADDR_INET> gateways;
    std::vector<SOCKADDR_INET> dnsServers;

    bool IsUp() const { return operStatus == IfOperStatusUp; }
};

// Все адаптеры, кроме loopback. Бросает std::system_error при сбое API.
std::vector<NetAdapter> EnumerateAdapters();

// Поиск по ifIndex ("17"), GUID ("{...}") или псевдониму ("happ-xray"), без учёта регистра.
const NetAdapter* FindAdapter(const std::vector<NetAdapter>& adapters, std::wstring_view key);

const NetAdapter* FindAdapter(const std::vector<NetAdapter>& adapters, NET_LUID luid);

} // namespace approute
