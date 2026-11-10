#pragma once

#include "core/Win.h"

#include <string>
#include <vector>

namespace approute {

// Разрешение имён через заданный интерфейс (DnsQueryEx, Windows 11+):
//   1) DNS-серверы самого интерфейса по UDP;
//   2) если они не ответили (таймаут, отказ, блокировка порта 53 VPN-клиентом) — DNS-over-HTTPS
//      через тот же интерфейс.
// Отрицательный ответ (имя не существует) считается окончательным — запасной путь не пробуем.
// Запросы выполняет служба DNS-клиента Windows; отправку через нужный интерфейс обеспечивает
// InterfaceIndex. Системный кэш DNS не используется (DNS_QUERY_BYPASS_CACHE).

struct DohServer {
    std::wstring templateUrl;   // https://cloudflare-dns.com/dns-query
    SOCKADDR_INET address{};    // IP сервера (порт 443)
};

// Cloudflare и Google.
std::vector<DohServer> DefaultDohServers();

struct DnsInterface {
    NET_IFINDEX ifIndex = 0;                 // индекс IPv4 (для DnsQueryEx)
    std::vector<SOCKADDR_INET> dnsServers;   // DNS-серверы интерфейса
    bool hasIpv4 = false;
    bool hasIpv6 = false;                    // глобальный IPv6 — иначе AAAA не запрашиваем
};

struct NetAdapter;

// Параметры интерфейса для ResolveViaInterface по данным адаптера.
DnsInterface MakeDnsInterface(const NetAdapter& adapter);

enum class DnsOutcome {
    Resolved,      // есть адреса
    NoSuchName,    // имя не существует / нет записей
    Failed,        // ни один способ не ответил
};

struct DnsAnswer {
    DnsOutcome outcome = DnsOutcome::Failed;
    std::vector<SOCKADDR_INET> addresses;   // порт 0
    ULONG ttl = 0;                          // минимальный TTL ответа, с
    const wchar_t* via = L"";               // "DNS интерфейса" / "DoH"
    LONG lastError = 0;                     // DNS_STATUS последней неудачи
};

// family: AF_INET, AF_INET6 или AF_UNSPEC.
DnsAnswer ResolveViaInterface(const std::wstring& name, int family, const DnsInterface& iface,
                              const std::vector<DohServer>& doh);

} // namespace approute
