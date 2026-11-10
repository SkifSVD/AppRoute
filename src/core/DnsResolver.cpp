#include "core/DnsResolver.h"
#include "core/NetAdapters.h"
#include "core/Util.h"

#include <windns.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>

namespace approute {

namespace {

constexpr DWORD kUdpTimeoutMs = 2500;
constexpr DWORD kDohTimeoutMs = 5000;

SOCKADDR_INET Ipv4(const wchar_t* text, USHORT port)
{
    SOCKADDR_INET a{};
    a.Ipv4.sin_family = AF_INET;
    a.Ipv4.sin_port = htons(port);
    InetPtonW(AF_INET, text, &a.Ipv4.sin_addr);
    return a;
}

// DnsQueryEx принимает адреса серверов только с портом 0 (иначе ERROR_INVALID_PARAMETER):
// порт определяется типом сервера (53 / 443 / 853).
void CopySockaddr(const SOCKADDR_INET& from, CHAR (&to)[DNS_ADDR_MAX_SOCKADDR_LENGTH])
{
    std::memset(to, 0, sizeof(to));
    SOCKADDR_INET a = from;
    if (a.si_family == AF_INET) {
        a.Ipv4.sin_port = 0;
        std::memcpy(to, &a.Ipv4, sizeof(a.Ipv4));
    } else {
        a.Ipv6.sin6_port = 0;
        std::memcpy(to, &a.Ipv6, sizeof(a.Ipv6));
    }
}

struct QueryContext {
    HANDLE done = nullptr;
    DNS_QUERY_RESULT result{};
};

VOID WINAPI OnQueryComplete(PVOID context, PDNS_QUERY_RESULT)
{
    SetEvent(static_cast<QueryContext*>(context)->done);
}

// Набор серверов для одного способа: либо обычные DNS-серверы (pDnsServerList), либо
// пользовательские DoH-серверы (DNS_QUERY_REQUEST3).
struct ServerSet {
    std::vector<std::byte> addrArray;          // DNS_ADDR_ARRAY переменной длины
    std::vector<DNS_CUSTOM_SERVER> custom;
};

ServerSet PlainServers(const std::vector<SOCKADDR_INET>& addresses)
{
    ServerSet set;
    const size_t n = addresses.size();
    set.addrArray.resize(sizeof(DNS_ADDR_ARRAY) + (n > 1 ? (n - 1) * sizeof(DNS_ADDR) : 0));
    auto* arr = reinterpret_cast<DNS_ADDR_ARRAY*>(set.addrArray.data());
    arr->MaxCount = static_cast<DWORD>(n);
    arr->AddrCount = static_cast<DWORD>(n);
    for (size_t i = 0; i < n; ++i) {
        CopySockaddr(addresses[i], arr->AddrArray[i].MaxSa);
    }
    return set;
}

// Один запрос DnsQueryEx с таймаутом. records — освобождать через DnsRecordListFree.
DNS_STATUS QueryOnce(const std::wstring& name, WORD type, ULONG ifIndex,
                     ServerSet& servers, DWORD timeoutMs, PDNS_RECORD& records)
{
    records = nullptr;
    QueryContext ctx;
    ctx.done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx.done) {
        return static_cast<DNS_STATUS>(GetLastError());
    }
    ctx.result.Version = DNS_QUERY_RESULTS_VERSION1;

    DNS_QUERY_REQUEST3 request{};
    request.Version = servers.custom.empty() ? DNS_QUERY_REQUEST_VERSION1 : DNS_QUERY_REQUEST_VERSION3;
    request.QueryName = name.c_str();
    request.QueryType = type;
    request.QueryOptions = DNS_QUERY_BYPASS_CACHE;
    // Со списком обычных серверов InterfaceIndex недопустим (ERROR_INVALID_PARAMETER):
    // туда ходим только к серверам в подсети интерфейса, маршрут и так через него
    request.InterfaceIndex = servers.addrArray.empty() ? ifIndex : 0;
    request.pQueryCompletionCallback = &OnQueryComplete;
    request.pQueryContext = &ctx;
    if (!servers.addrArray.empty()) {
        request.pDnsServerList = reinterpret_cast<PDNS_ADDR_ARRAY>(servers.addrArray.data());
    }
    request.cCustomServers = static_cast<DWORD>(servers.custom.size());
    request.pCustomServers = servers.custom.empty() ? nullptr : servers.custom.data();

    DNS_QUERY_CANCEL cancel{};
    DNS_STATUS status = DnsQueryEx(reinterpret_cast<PDNS_QUERY_REQUEST>(&request), &ctx.result, &cancel);
    if (status == DNS_REQUEST_PENDING) {
        if (WaitForSingleObject(ctx.done, timeoutMs) != WAIT_OBJECT_0) {
            DnsCancelQuery(&cancel);
            WaitForSingleObject(ctx.done, INFINITE);   // колбэк вызывается и при отмене
        }
        status = ctx.result.QueryStatus;
    }
    CloseHandle(ctx.done);
    records = ctx.result.pQueryRecords;
    return status;
}

constexpr ULONGLONG kPlainRetryMs = 60'000;
SRWLOCK g_plainLock = SRWLOCK_INIT;
std::map<ULONG, ULONGLONG> g_plainFailedAt;   // ifIndex -> время последней неудачи

bool PlainRecentlyFailed(ULONG ifIndex)
{
    AcquireSRWLockShared(&g_plainLock);
    const auto it = g_plainFailedAt.find(ifIndex);
    const bool failed = it != g_plainFailedAt.end() && GetTickCount64() - it->second < kPlainRetryMs;
    ReleaseSRWLockShared(&g_plainLock);
    return failed;
}

void NotePlainFailure(ULONG ifIndex)
{
    AcquireSRWLockExclusive(&g_plainLock);
    g_plainFailedAt[ifIndex] = GetTickCount64();
    ReleaseSRWLockExclusive(&g_plainLock);
}

bool IsNegative(DNS_STATUS s)
{
    return s == DNS_ERROR_RCODE_NAME_ERROR || s == DNS_INFO_NO_RECORDS;
}

// A и/или AAAA через один набор серверов. true — получен окончательный ответ (адреса или
// «имени нет»), false — серверы не ответили, стоит пробовать следующий способ.
bool ResolveWith(const std::wstring& name, const std::vector<WORD>& types, ULONG ifIndex,
                 ServerSet& servers, DWORD timeoutMs, DnsAnswer& answer)
{
    bool anyFinal = false;
    bool anyNegative = false;
    for (WORD type : types) {
        PDNS_RECORD records = nullptr;
        const DNS_STATUS status = QueryOnce(name, type, ifIndex, servers, timeoutMs, records);
        if (status == ERROR_SUCCESS) {
            anyFinal = true;
            for (auto* r = records; r; r = r->pNext) {
                if (r->Flags.S.Section != DnsSectionAnswer) {
                    continue;
                }
                SOCKADDR_INET a{};
                if (r->wType == DNS_TYPE_A && type == DNS_TYPE_A) {
                    a.Ipv4.sin_family = AF_INET;
                    a.Ipv4.sin_addr.s_addr = r->Data.A.IpAddress;
                } else if (r->wType == DNS_TYPE_AAAA && type == DNS_TYPE_AAAA) {
                    a.Ipv6.sin6_family = AF_INET6;
                    std::memcpy(&a.Ipv6.sin6_addr, &r->Data.AAAA.Ip6Address, sizeof(IN6_ADDR));
                } else {
                    continue;   // CNAME и прочее
                }
                answer.addresses.push_back(a);
                answer.ttl = std::min<ULONG>(answer.ttl, r->dwTtl);
            }
        } else if (IsNegative(status)) {
            anyFinal = true;
            anyNegative = true;
        } else {
            answer.lastError = status;
        }
        if (records) {
            DnsRecordListFree(records, DnsFreeRecordList);
        }
    }
    if (!anyFinal) {
        return false;
    }
    answer.outcome = !answer.addresses.empty() ? DnsOutcome::Resolved : DnsOutcome::NoSuchName;
    if (answer.ttl == std::numeric_limits<ULONG>::max()) {
        answer.ttl = 30;   // отрицательный ответ без записей — кэшируем ненадолго
    }
    (void)anyNegative;
    return true;
}

} // namespace

// Запрос к серверу пойдёт через адаптер: сервер в его подсети или лучший маршрут — через него.
static bool ReachableVia(const NetAdapter& adapter, const SOCKADDR_INET& server)
{
    for (const auto& u : adapter.unicast) {
        if (InPrefix(server, u.address, u.prefixLength)) {
            return true;
        }
    }
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    if (GetBestRoute2(nullptr, 0, nullptr, &server, 0, &route, &source) != NO_ERROR) {
        return false;
    }
    return route.InterfaceLuid.Value == adapter.luid.Value;
}

DnsInterface MakeDnsInterface(const NetAdapter& adapter, const std::vector<NrptRule>& nrpt)
{
    DnsInterface d;
    d.ifIndex = adapter.ifIndex ? adapter.ifIndex : adapter.ipv6IfIndex;
    for (const auto& u : adapter.unicast) {
        if (u.address.si_family == AF_INET) {
            d.hasIpv4 = true;
        } else if (u.address.si_family == AF_INET6 && !IN6_IS_ADDR_LINKLOCAL(&u.address.Ipv6.sin6_addr)) {
            d.hasIpv6 = true;
        }
    }
    for (const auto& s : adapter.dnsServers) {
        if (ReachableVia(adapter, s)) {
            d.dnsServers.push_back(s);
        }
    }
    for (const auto& rule : nrpt) {
        NrptRule own{rule.namespaces, {}};
        for (const auto& s : rule.servers) {
            if (ReachableVia(adapter, s)) {
                own.servers.push_back(s);
            }
        }
        if (!own.servers.empty()) {
            d.nrpt.push_back(std::move(own));
        }
    }
    return d;
}

DnsInterface MakeDnsInterface(const NetAdapter& adapter)
{
    return MakeDnsInterface(adapter, LoadNrptRules());
}

std::vector<DohServer> DefaultDohServers()
{
    return {
        {L"https://cloudflare-dns.com/dns-query", Ipv4(L"1.1.1.1", 443)},
        {L"https://dns.google/dns-query", Ipv4(L"8.8.8.8", 443)},
    };
}

DnsAnswer ResolveViaInterface(const std::wstring& name, int family, const DnsInterface& iface,
                              const std::vector<DohServer>& doh)
{
    std::vector<WORD> types;
    if ((family == AF_INET || family == AF_UNSPEC) && iface.hasIpv4) {
        types.push_back(DNS_TYPE_A);
    }
    if ((family == AF_INET6 || family == AF_UNSPEC) && iface.hasIpv6) {
        types.push_back(DNS_TYPE_AAAA);
    }

    DnsAnswer answer;
    answer.ttl = std::numeric_limits<ULONG>::max();
    if (types.empty()) {
        answer.outcome = DnsOutcome::NoSuchName;   // у интерфейса нет адресов нужного семейства
        answer.ttl = 0;
        return answer;
    }

    // 0) Пространство имён NRPT с серверами через этот интерфейс (корпоративный DNS VPN):
    //    ответ только от них — внутреннее имя не должно уйти во внешний DoH
    if (const NrptRule* rule = MatchNrpt(iface.nrpt, name)) {
        ServerSet servers = PlainServers(rule->servers);
        if (ResolveWith(name, types, iface.ifIndex, servers, kUdpTimeoutMs, answer)) {
            answer.via = L"NRPT";
            return answer;
        }
        answer.outcome = DnsOutcome::Failed;
        answer.ttl = 0;
        return answer;
    }

    // 1) DNS-серверы интерфейса (если недавно не отвечали — сразу к DoH, чтобы не ждать таймаут
    //    на каждом имени: VPN-клиент может блокировать порт 53 в обход туннеля)
    if (!iface.dnsServers.empty() && !PlainRecentlyFailed(iface.ifIndex)) {
        ServerSet servers = PlainServers(iface.dnsServers);
        if (ResolveWith(name, types, iface.ifIndex, servers, kUdpTimeoutMs, answer)) {
            answer.via = L"DNS интерфейса";
            return answer;
        }
        NotePlainFailure(iface.ifIndex);
    }

    // 2) DNS-over-HTTPS через тот же интерфейс
    if (!doh.empty()) {
        ServerSet servers;
        for (const auto& d : doh) {
            DNS_CUSTOM_SERVER cs{};
            cs.dwServerType = DNS_CUSTOM_SERVER_TYPE_DOH;
            cs.pwszTemplate = const_cast<PWSTR>(d.templateUrl.c_str());
            CopySockaddr(d.address, cs.MaxSa);
            servers.custom.push_back(cs);
        }
        answer.addresses.clear();
        if (ResolveWith(name, types, iface.ifIndex, servers, kDohTimeoutMs, answer)) {
            answer.via = L"DoH";
            return answer;
        }
    }

    answer.outcome = DnsOutcome::Failed;
    answer.ttl = 0;
    return answer;
}

} // namespace approute
