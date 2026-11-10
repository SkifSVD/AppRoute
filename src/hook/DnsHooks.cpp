// Перехват разрешения имён: getaddrinfo / GetAddrInfoW / GetAddrInfoExW.
// Имена разрешаются через выбранный интерфейс (core/DnsResolver: DNS интерфейса, иначе DoH
// через него). Так DNS не уходит в системный резолвер, который ходит через основной канал.
//
// Перехватываем только обычные запросы по имени узла. Числовые адреса, запросы со службой
// (AI_NUMERICHOST, getaddrinfo по порту-службе) и всё, чего резолвер не покрыл, отдаём
// оригиналу. APPROUTE_DNS=system отключает перехват.

#include "DnsHooks.h"
#include "AdapterResolver.h"
#include "Log.h"

#include "core/DnsResolver.h"
#include "core/NetAdapters.h"
#include "core/Policy.h"
#include "core/Process.h"
#include "core/Socks5.h"
#include "core/Util.h"

#include <ws2tcpip.h>

#include <MinHook.h>

#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

namespace approute::hook {

namespace {

AdapterResolver* g_resolver = nullptr;
FakeIpPool* g_fake = nullptr;
UnavailablePolicy g_policy;
std::vector<DohServer> g_doh;

decltype(&::getaddrinfo) Real_getaddrinfo = &::getaddrinfo;
decltype(&::GetAddrInfoW) Real_GetAddrInfoW = &::GetAddrInfoW;
decltype(&::GetAddrInfoExW) Real_GetAddrInfoExW = &::GetAddrInfoExW;
decltype(&::freeaddrinfo) Real_freeaddrinfo = &::freeaddrinfo;
decltype(&::FreeAddrInfoW) Real_FreeAddrInfoW = &::FreeAddrInfoW;
void(WSAAPI* Real_FreeAddrInfoExW)(PADDRINFOEXW) = &::FreeAddrInfoExW;

// Списки, которые выделили мы (CRT-куча через calloc): их нельзя отдавать оригинальному
// free из ws2_32 — он использует другой аллокатор. Ключ — головной указатель.
SRWLOCK g_ownLock = SRWLOCK_INIT;
std::unordered_set<const void*> g_ownResults;

void RegisterOwn(const void* head)
{
    if (!head) {
        return;
    }
    AcquireSRWLockExclusive(&g_ownLock);
    g_ownResults.insert(head);
    ReleaseSRWLockExclusive(&g_ownLock);
}

bool TakeOwn(const void* head)
{
    AcquireSRWLockExclusive(&g_ownLock);
    const bool ours = g_ownResults.erase(head) != 0;
    ReleaseSRWLockExclusive(&g_ownLock);
    return ours;
}

// Освобождение нашего списка: ai_addr и узлы выделены calloc. Раскладка addrinfo и addrinfoW
// для ai_next/ai_addr совпадает по смещениям, поэтому одна функция подходит для обоих.
template <typename AI>
void FreeOwn(AI* list)
{
    while (list) {
        AI* next = list->ai_next;
        std::free(list->ai_addr);
        std::free(list);
        list = next;
    }
}

// Параметры выбранного интерфейса для резолвера, обновляются не чаще раза в 2 с.
SRWLOCK g_ifaceLock = SRWLOCK_INIT;
DnsInterface g_iface;
ULONGLONG g_ifaceAt = 0;

bool CurrentInterface(DnsInterface& out)
{
    AcquireSRWLockExclusive(&g_ifaceLock);
    if (g_ifaceAt == 0 || GetTickCount64() - g_ifaceAt > 2000) {
        NET_LUID luid{};
        if (ConvertInterfaceGuidToLuid(&g_resolver->Guid(), &luid) == NO_ERROR) {
            try {
                const auto adapters = EnumerateAdapters();
                if (const auto* a = FindAdapter(adapters, luid)) {
                    g_iface = MakeDnsInterface(*a);
                }
            } catch (...) {
            }
        }
        g_ifaceAt = GetTickCount64();
    }
    out = g_iface;
    ReleaseSRWLockExclusive(&g_ifaceLock);
    return out.ifIndex != 0 && (out.hasIpv4 || out.hasIpv6);
}

int FamilyFromHints(const addrinfo* hints)
{
    return hints && hints->ai_family != AF_UNSPEC ? hints->ai_family : AF_UNSPEC;
}

bool ShouldResolveHere(const char* node, const addrinfo* hints)
{
    if (!node || !*node) {
        return false;   // привязка пассивного сокета — не наш случай
    }
    if (hints && (hints->ai_flags & AI_NUMERICHOST)) {
        return false;
    }
    // Числовой адрес резолвить не нужно
    SOCKADDR_INET tmp{};
    if (InetPtonA(AF_INET, node, &tmp.Ipv4.sin_addr) == 1 || InetPtonA(AF_INET6, node, &tmp.Ipv6.sin6_addr) == 1) {
        return false;
    }
    return true;
}

// Собрать addrinfo-список из адресов. Порт/служба — как в оригинальном запросе, поэтому порт
// проставляем здесь по service/hints не умеем надёжно → порт 0, вызывающий код обычно задаёт
// порт сам (connect с sockaddr) либо передаёт service; поэтому реальную привязку порта делаем
// только когда service числовой.
template <typename CharT>
USHORT PortFromService(const CharT* service, const addrinfo* hints)
{
    if (!service) {
        return 0;
    }
    unsigned long port = 0;
    for (const CharT* p = service; *p; ++p) {
        if (*p < '0' || *p > '9') {
            return 0;   // имя службы (например "https") — пусть резолвит оригинал
        }
        port = port * 10 + static_cast<unsigned long>(*p - '0');
    }
    (void)hints;
    return htons(static_cast<USHORT>(port));
}

addrinfoW* BuildResultW(const DnsAnswer& answer, USHORT port, int sockType, int protocol)
{
    addrinfoW* head = nullptr;
    addrinfoW** tail = &head;
    for (const auto& a : answer.addresses) {
        auto* ai = static_cast<addrinfoW*>(std::calloc(1, sizeof(addrinfoW)));
        if (!ai) {
            break;
        }
        ai->ai_family = a.si_family;
        ai->ai_socktype = sockType;
        ai->ai_protocol = protocol;
        if (a.si_family == AF_INET) {
            auto* sa = static_cast<sockaddr_in*>(std::calloc(1, sizeof(sockaddr_in)));
            *sa = a.Ipv4;
            sa->sin_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in);
        } else {
            auto* sa = static_cast<sockaddr_in6*>(std::calloc(1, sizeof(sockaddr_in6)));
            *sa = a.Ipv6;
            sa->sin6_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in6);
        }
        *tail = ai;
        tail = &ai->ai_next;
    }
    return head;
}

ADDRINFOEXW* BuildResultEx(const DnsAnswer& answer, USHORT port, int sockType, int protocol)
{
    ADDRINFOEXW* head = nullptr;
    ADDRINFOEXW** tail = &head;
    for (const auto& a : answer.addresses) {
        auto* ai = static_cast<ADDRINFOEXW*>(std::calloc(1, sizeof(ADDRINFOEXW)));
        if (!ai) {
            break;
        }
        ai->ai_family = a.si_family;
        ai->ai_socktype = sockType;
        ai->ai_protocol = protocol;
        if (a.si_family == AF_INET) {
            auto* sa = static_cast<sockaddr_in*>(std::calloc(1, sizeof(sockaddr_in)));
            *sa = a.Ipv4;
            sa->sin_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in);
        } else {
            auto* sa = static_cast<sockaddr_in6*>(std::calloc(1, sizeof(sockaddr_in6)));
            *sa = a.Ipv6;
            sa->sin6_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in6);
        }
        *tail = ai;
        tail = &ai->ai_next;
    }
    return head;
}

enum class Resolution {
    Answer,   // ответ в answer (адреса или NoSuchName)
    System,   // отдать запрос системному резолверу
    Block,    // вернуть ошибку: DNS мимо интерфейса запрещён
};

// Общая часть: разрешить имя через интерфейс. Если интерфейс недоступен или резолвер не дал
// окончательного ответа — по политике правила: системный резолвер (default) или ошибка (block).
Resolution ResolveName(const std::wstring& name, int family, DnsAnswer& answer)
{
    if (g_fake) {
        // Правило «прокси»: имя разрешит прокси при соединении. localhost и имена без точки
        // (узлы локальной сети) — системе
        if (EqualsIgnoreCase(name, L"localhost") || name.find(L'.') == std::wstring::npos) {
            return Resolution::System;
        }
        const auto host = ProxyHostName(name);
        if (!host) {
            return Resolution::System;
        }
        SOCKADDR_INET a = g_fake->Allocate(*host);
        if (family == AF_INET6) {
            // Только IPv6 — ::ffff:служебный IPv4 (двухстековые сокеты)
            SOCKADDR_INET v6{};
            v6.Ipv6.sin6_family = AF_INET6;
            v6.Ipv6.sin6_addr.u.Byte[10] = 0xFF;
            v6.Ipv6.sin6_addr.u.Byte[11] = 0xFF;
            std::memcpy(&v6.Ipv6.sin6_addr.u.Byte[12], &a.Ipv4.sin_addr, 4);
            a = v6;
        }
        answer = {};
        answer.outcome = DnsOutcome::Resolved;
        answer.addresses.push_back(a);
        answer.via = L"прокси";
        return Resolution::Answer;
    }
    DnsInterface iface;
    const bool available = CurrentInterface(iface);
    if (available) {
        answer = ResolveViaInterface(name, family, iface, g_doh);
        if (answer.outcome != DnsOutcome::Failed) {
            return Resolution::Answer;
        }
    }
    const wchar_t* reason = available ? L"резолвер интерфейса не ответил" : L"интерфейс недоступен";
    if (g_policy.UseSystemDns()) {
        Log(L"DNS %ls: %ls — системный резолвер (default)", name.c_str(), reason);
        return Resolution::System;
    }
    Log(L"DNS %ls: %ls — заблокировано", name.c_str(), reason);
    return Resolution::Block;
}

std::wstring Widen(const char* s)
{
    const int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    std::wstring w(static_cast<size_t>(len > 0 ? len - 1 : 0), L'\0');
    if (len > 1) {
        MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), len);
    }
    return w;
}

int WSAAPI Hook_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result)
{
    if (!node || (hints && (hints->ai_flags & AI_NUMERICHOST))) {
        return Real_GetAddrInfoW(node, service, hints, result);
    }
    SOCKADDR_INET tmp{};
    if (InetPtonW(AF_INET, node, &tmp.Ipv4.sin_addr) == 1 || InetPtonW(AF_INET6, node, &tmp.Ipv6.sin6_addr) == 1) {
        return Real_GetAddrInfoW(node, service, hints, result);
    }

    const int family = hints && hints->ai_family != AF_UNSPEC ? hints->ai_family : AF_UNSPEC;
    DnsAnswer answer;
    switch (ResolveName(node, family, answer)) {
    case Resolution::System: return Real_GetAddrInfoW(node, service, hints, result);
    case Resolution::Block: *result = nullptr; return WSATRY_AGAIN;
    case Resolution::Answer: break;
    }
    if (answer.outcome == DnsOutcome::NoSuchName) {
        *result = nullptr;
        return WSAHOST_NOT_FOUND;
    }
    const USHORT port = PortFromService(service, reinterpret_cast<const addrinfo*>(hints));
    const int sockType = hints ? hints->ai_socktype : 0;
    const int protocol = hints ? hints->ai_protocol : 0;
    *result = BuildResultW(answer, port, sockType, protocol);
    RegisterOwn(*result);
    Log(L"GetAddrInfoW %ls → %zu адр. через %ls", node, answer.addresses.size(), answer.via);
    return *result ? 0 : WSA_NOT_ENOUGH_MEMORY;
}

int WSAAPI Hook_getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** result)
{
    if (!ShouldResolveHere(node, hints)) {
        return Real_getaddrinfo(node, service, hints, result);
    }
    const int family = FamilyFromHints(hints);
    DnsAnswer answer;
    switch (ResolveName(Widen(node), family, answer)) {
    case Resolution::System: return Real_getaddrinfo(node, service, hints, result);
    case Resolution::Block: *result = nullptr; return WSATRY_AGAIN;
    case Resolution::Answer: break;
    }
    if (answer.outcome == DnsOutcome::NoSuchName) {
        *result = nullptr;
        return WSAHOST_NOT_FOUND;
    }
    // Строим ANSI addrinfo
    const USHORT port = PortFromService(service, hints);
    const int sockType = hints ? hints->ai_socktype : 0;
    const int protocol = hints ? hints->ai_protocol : 0;
    addrinfo* head = nullptr;
    addrinfo** tail = &head;
    for (const auto& a : answer.addresses) {
        auto* ai = static_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
        if (!ai) {
            break;
        }
        ai->ai_family = a.si_family;
        ai->ai_socktype = sockType;
        ai->ai_protocol = protocol;
        if (a.si_family == AF_INET) {
            auto* sa = static_cast<sockaddr_in*>(std::calloc(1, sizeof(sockaddr_in)));
            *sa = a.Ipv4;
            sa->sin_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in);
        } else {
            auto* sa = static_cast<sockaddr_in6*>(std::calloc(1, sizeof(sockaddr_in6)));
            *sa = a.Ipv6;
            sa->sin6_port = port;
            ai->ai_addr = reinterpret_cast<sockaddr*>(sa);
            ai->ai_addrlen = sizeof(sockaddr_in6);
        }
        *tail = ai;
        tail = &ai->ai_next;
    }
    if (!head) {
        return WSA_NOT_ENOUGH_MEMORY;
    }
    *result = head;
    RegisterOwn(head);
    Log(L"getaddrinfo %hs → %zu адр. через %ls", node, answer.addresses.size(), answer.via);
    return 0;
}

// GetAddrInfoExW: поддерживаем только синхронный вызов по имени (lpOverlapped == nullptr).
// Асинхронные и прочие сложные варианты (name/DNS options) отдаём оригиналу.
int WSAAPI Hook_GetAddrInfoExW(PCWSTR name, PCWSTR serviceName, DWORD nameSpace, LPGUID nspId,
                               const ADDRINFOEXW* hints, PADDRINFOEXW* result, timeval* timeout,
                               LPOVERLAPPED overlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE completion,
                               LPHANDLE handle)
{
    auto callReal = [&] {
        return Real_GetAddrInfoExW(name, serviceName, nameSpace, nspId, hints, result, timeout,
                                   overlapped, completion, handle);
    };
    if (overlapped || completion || !name || (hints && (hints->ai_flags & AI_NUMERICHOST))) {
        return callReal();
    }
    SOCKADDR_INET tmp{};
    if (InetPtonW(AF_INET, name, &tmp.Ipv4.sin_addr) == 1 || InetPtonW(AF_INET6, name, &tmp.Ipv6.sin6_addr) == 1) {
        return callReal();
    }

    const int family = hints && hints->ai_family != AF_UNSPEC ? hints->ai_family : AF_UNSPEC;
    DnsAnswer answer;
    switch (ResolveName(name, family, answer)) {
    case Resolution::System: return callReal();
    case Resolution::Block: *result = nullptr; return WSATRY_AGAIN;
    case Resolution::Answer: break;
    }
    if (answer.outcome == DnsOutcome::NoSuchName) {
        *result = nullptr;
        return WSAHOST_NOT_FOUND;
    }

    const USHORT port = PortFromService(serviceName, nullptr);
    const int sockType = hints ? hints->ai_socktype : 0;
    const int protocol = hints ? hints->ai_protocol : 0;
    // ADDRINFOEXW начинается теми же полями, что addrinfoW; строим addrinfoW-совместимый список
    auto* head = BuildResultEx(answer, port, sockType, protocol);
    *result = head;
    RegisterOwn(head);
    Log(L"GetAddrInfoExW %ls → %zu адр. через %ls", name, answer.addresses.size(), answer.via);
    return head ? 0 : WSA_NOT_ENOUGH_MEMORY;
}

void WSAAPI Hook_freeaddrinfo(addrinfo* list)
{
    if (list && TakeOwn(list)) {
        FreeOwn(list);
    } else {
        Real_freeaddrinfo(list);
    }
}

void WSAAPI Hook_FreeAddrInfoW(addrinfoW* list)
{
    if (list && TakeOwn(list)) {
        FreeOwn(list);
    } else {
        Real_FreeAddrInfoW(list);
    }
}

void WSAAPI Hook_FreeAddrInfoExW(ADDRINFOEXW* list)
{
    if (list && TakeOwn(list)) {
        FreeOwn(list);
    } else {
        Real_FreeAddrInfoExW(list);
    }
}

template <typename T>
void HookApi(const char* name, T* detour, T** original)
{
    const MH_STATUS st = MH_CreateHookApi(L"ws2_32", name, reinterpret_cast<LPVOID>(detour),
                                          reinterpret_cast<LPVOID*>(original));
    // FreeAddrInfoW и freeaddrinfo в ws2_32 — одна и та же функция: второй хук на тот же адрес
    // не нужен (ALREADY_CREATED), оригинал уже перенаправлен первым.
    if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED) {
        Log(L"не удалось перехватить %hs (DNS): %hs", name, MH_StatusToString(st));
    }
}

} // namespace

bool CreateDnsHooks(AdapterResolver& resolver, const UnavailablePolicy& policy, FakeIpPool* fake)
{
    wchar_t mode[16] = {};
    if (GetEnvironmentVariableW(kEnvDns, mode, 16) != 0 && EqualsIgnoreCase(mode, L"system")) {
        Log(L"DNS: системный резолвер (APPROUTE_DNS=system)");
        return false;
    }
    g_resolver = &resolver;
    g_fake = fake;
    g_policy = policy;
    g_doh = DefaultDohServers();

    HookApi("getaddrinfo", &Hook_getaddrinfo, &Real_getaddrinfo);
    HookApi("GetAddrInfoW", &Hook_GetAddrInfoW, &Real_GetAddrInfoW);
    HookApi("GetAddrInfoExW", &Hook_GetAddrInfoExW, &Real_GetAddrInfoExW);
    HookApi("freeaddrinfo", &Hook_freeaddrinfo, &Real_freeaddrinfo);
    HookApi("FreeAddrInfoW", &Hook_FreeAddrInfoW, &Real_FreeAddrInfoW);
    HookApi("FreeAddrInfoExW", &Hook_FreeAddrInfoExW, &Real_FreeAddrInfoExW);
    return true;
}

} // namespace approute::hook
