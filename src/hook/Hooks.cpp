// Перехват Winsock: перед соединением/отправкой сокет привязывается к IP выбранного интерфейса.
// Windows (strong host model) отправляет пакеты привязанного сокета только маршрутами этого
// интерфейса, поэтому трафик уходит через него, какой бы интерфейс ни был основным.
//
// Если у интерфейса нет адреса нужного семейства (VPN отключён, нет IPv6), поведение задаёт
// правило (#9): block — WSAENETUNREACH, default — соединение идёт маршрутом по умолчанию.
//
// Правило «прокси» (#17): TCP-соединения вместо привязки к интерфейсу идут через SOCKS5-прокси
// (соединение с прокси и рукопожатие — синхронно, внутри connect/ConnectEx), имена разрешает
// прокси (служебные адреса из DnsHooks). UDP — через UDP ASSOCIATE (#46, UdpRelay): датаграммы
// идут на внутренний сокет реле, адрес отправителя в ответах подменяется исходным. Локальные
// адреса (loopback, подсети интерфейсов) — напрямую.

#include "Hooks.h"
#include "AdapterResolver.h"
#include "DnsHooks.h"
#include "Log.h"
#include "ProcessHooks.h"
#include "UdpRelay.h"

#include "core/Policy.h"
#include "core/Process.h"
#include "core/ProxyCredentials.h"
#include "core/Socks5.h"
#include "core/Util.h"

#include <MinHook.h>
#include <mswsock.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace approute::hook {

namespace {

AdapterResolver g_resolver;
UnavailablePolicy g_policy;
bool g_installed = false;

// Правило «прокси» (#17)
std::optional<SOCKADDR_INET> g_proxy;
std::optional<ProxyCredential> g_credential;   // логин и пароль прокси (#56), из диспетчера учётных данных
FakeIpPool g_fakeIps;
bool g_fakeDns = false;
SRWLOCK g_proxiedLock = SRWLOCK_INIT;
std::unordered_map<SOCKET, sockaddr_storage> g_proxied;   // сокет → адрес, с которым соединялась программа

// Оригиналы. До установки перехватов указывают на сами функции Winsock.
decltype(&::connect) Real_connect = &::connect;
decltype(&::WSAConnect) Real_WSAConnect = &::WSAConnect;
decltype(&::bind) Real_bind = &::bind;
decltype(&::sendto) Real_sendto = &::sendto;
decltype(&::WSASendTo) Real_WSASendTo = &::WSASendTo;
decltype(&::WSASendMsg) Real_WSASendMsg = &::WSASendMsg;
decltype(&::WSAIoctl) Real_WSAIoctl = &::WSAIoctl;
decltype(&::getsockname) Real_getsockname = &::getsockname;
decltype(&::listen) Real_listen = &::listen;
decltype(&::closesocket) Real_closesocket = &::closesocket;
decltype(&::getpeername) Real_getpeername = &::getpeername;
decltype(&::setsockopt) Real_setsockopt = &::setsockopt;
// UDP через прокси (#46): приём и завершение асинхронных операций — подмена адреса отправителя
decltype(&::recvfrom) Real_recvfrom = &::recvfrom;
decltype(&::WSARecvFrom) Real_WSARecvFrom = &::WSARecvFrom;
decltype(&::WSAGetOverlappedResult) Real_WSAGetOverlappedResult = &::WSAGetOverlappedResult;
decltype(&::GetOverlappedResult) Real_GetOverlappedResult = &::GetOverlappedResult;
decltype(&::GetOverlappedResultEx) Real_GetOverlappedResultEx = &::GetOverlappedResultEx;
decltype(&::GetQueuedCompletionStatus) Real_GetQueuedCompletionStatus = &::GetQueuedCompletionStatus;
decltype(&::GetQueuedCompletionStatusEx) Real_GetQueuedCompletionStatusEx = &::GetQueuedCompletionStatusEx;
LPFN_WSARECVMSG Real_WSARecvMsg = nullptr;

SRWLOCK g_connectExLock = SRWLOCK_INIT;
LPFN_CONNECTEX Real_ConnectEx = nullptr;

// Двухстековые IPv6-сокеты, привязанные к "::" — настоящий bind откладывается до первого
// соединения, когда станет известно семейство адреса назначения. Значение — порт (сетевой порядок).
SRWLOCK g_deferredLock = SRWLOCK_INIT;
std::unordered_map<SOCKET, USHORT> g_deferred;
// Двухстековые сокеты, которые пришлось привязать к "::" из-за getsockname до соединения (#20).
// Обычно это mDNS и другие локальные службы (UDP 5353 → ff02::fb) — им "::" и нужен. Перепривязать
// сокет нельзя, поэтому соединения и отправки с него за пределы локальной сети подчиняются
// политике правила: «блокировать» — блокируются, «маршрутом по умолчанию» — идут как есть.
std::unordered_map<SOCKET, int> g_earlyBound;   // значение — SO_TYPE

// --- адреса -------------------------------------------------------------------------------

bool ToInet(const sockaddr* sa, int len, SOCKADDR_INET& out)
{
    if (!sa) {
        return false;
    }
    out = {};
    if (sa->sa_family == AF_INET && len >= static_cast<int>(sizeof(sockaddr_in))) {
        std::memcpy(&out.Ipv4, sa, sizeof(sockaddr_in));
        return true;
    }
    if (sa->sa_family == AF_INET6 && len >= static_cast<int>(sizeof(sockaddr_in6))) {
        std::memcpy(&out.Ipv6, sa, sizeof(sockaddr_in6));
        return true;
    }
    return false;
}

// ::ffff:a.b.c.d → a.b.c.d
SOCKADDR_INET Unmap(const SOCKADDR_INET& a)
{
    if (a.si_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&a.Ipv6.sin6_addr)) {
        return a;
    }
    SOCKADDR_INET v4{};
    v4.Ipv4.sin_family = AF_INET;
    v4.Ipv4.sin_port = a.Ipv6.sin6_port;
    std::memcpy(&v4.Ipv4.sin_addr, &a.Ipv6.sin6_addr.u.Byte[12], 4);
    return v4;
}

USHORT PortOf(const SOCKADDR_INET& a)
{
    return a.si_family == AF_INET ? a.Ipv4.sin_port : a.Ipv6.sin6_port;
}

std::wstring Widen(const std::string& s)
{
    return std::wstring(s.begin(), s.end());   // имена для прокси — ASCII
}

std::wstring Describe(const SOCKADDR_INET& a)
{
    const auto port = ntohs(PortOf(a));
    return a.si_family == AF_INET6 ? L"[" + FormatAddress(a) + L"]:" + std::to_wstring(port)
                                   : FormatAddress(a) + L":" + std::to_wstring(port);
}

// Адрес для bind() сокета семейства socketFamily, соединяющегося с адресом семейства
// targetFamily (для двухстекового сокета и IPv4-цели — ::ffff:<IPv4 интерфейса>).
bool MakeBindAddress(ADDRESS_FAMILY socketFamily, ADDRESS_FAMILY targetFamily, USHORT port,
                     sockaddr_storage& out, int& outLen)
{
    SOCKADDR_INET src{};
    if (!g_resolver.GetBindAddress(targetFamily, src)) {
        return false;
    }
    out = {};
    if (socketFamily == AF_INET) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&out);
        *sin = src.Ipv4;
        sin->sin_port = port;
        outLen = sizeof(sockaddr_in);
        return true;
    }
    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&out);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = port;
    if (targetFamily == AF_INET6) {
        sin6->sin6_addr = src.Ipv6.sin6_addr;
    } else {
        sin6->sin6_addr.u.Byte[10] = 0xFF;
        sin6->sin6_addr.u.Byte[11] = 0xFF;
        std::memcpy(&sin6->sin6_addr.u.Byte[12], &src.Ipv4.sin_addr, 4);
    }
    outLen = sizeof(sockaddr_in6);
    return true;
}

std::optional<USHORT> TakeDeferred(SOCKET s)
{
    AcquireSRWLockExclusive(&g_deferredLock);
    std::optional<USHORT> port;
    if (auto it = g_deferred.find(s); it != g_deferred.end()) {
        port = it->second;
        g_deferred.erase(it);
    }
    ReleaseSRWLockExclusive(&g_deferredLock);
    return port;
}

// Выполнить отложенный bind как просил сам процесс — на "::" (для listen и т.п.).
void BindDeferredAsRequested(SOCKET s, USHORT port)
{
    sockaddr_in6 any{};
    any.sin6_family = AF_INET6;
    any.sin6_port = port;
    Real_bind(s, reinterpret_cast<const sockaddr*>(&any), sizeof(any));
}

// --- правило «прокси» (#17) ----------------------------------------------------------------

bool SocketInfo(SOCKET s, int& family, int& type)
{
    WSAPROTOCOL_INFOW info{};
    int len = sizeof(info);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&info), &len) != 0) {
        return false;
    }
    family = info.iAddressFamily;
    type = info.iSocketType;
    return true;
}

// Ждать готовности сокета (запись — соединение установлено, чтение — есть данные)
bool WaitSocket(SOCKET s, bool write, ULONGLONG deadline)
{
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            WSASetLastError(WSAETIMEDOUT);
            return false;
        }
        const ULONGLONG left = deadline - now;
        timeval tv{static_cast<long>(left / 1000), static_cast<long>((left % 1000) * 1000)};
        fd_set set;
        FD_ZERO(&set);
        FD_SET(s, &set);
        fd_set errors;
        FD_ZERO(&errors);
        FD_SET(s, &errors);
        const int rc = select(0, write ? nullptr : &set, write ? &set : nullptr, &errors, &tv);
        if (rc == SOCKET_ERROR) {
            return false;
        }
        if (FD_ISSET(s, &errors)) {
            int err = 0;
            int len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            WSASetLastError(err ? err : WSAECONNREFUSED);
            return false;
        }
        if (rc > 0) {
            return true;
        }
    }
}

bool SendAll(SOCKET s, std::string_view data, ULONGLONG deadline)
{
    while (!data.empty()) {
        const int n = send(s, data.data(), static_cast<int>(data.size()), 0);
        if (n > 0) {
            data.remove_prefix(static_cast<size_t>(n));
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK && WaitSocket(s, true, deadline)) {
            continue;
        }
        return false;
    }
    return true;
}

bool RecvExact(SOCKET s, char* out, size_t size, ULONGLONG deadline)
{
    size_t got = 0;
    while (got < size) {
        if (!WaitSocket(s, false, deadline)) {
            return false;
        }
        const int n = recv(s, out + got, static_cast<int>(size - got), 0);
        if (n > 0) {
            got += static_cast<size_t>(n);
        } else if (n == 0) {
            WSASetLastError(WSAECONNRESET);
            return false;
        } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
            return false;
        }
    }
    return true;
}

// Адрес прокси для сокета семейства family (двухстековому IPv6-сокету — ::ffff:IPv4)
bool ProxyAddressFor(SOCKET s, int family, sockaddr_storage& out, int& outLen)
{
    out = {};
    const SOCKADDR_INET& p = *g_proxy;
    if (family == AF_INET) {
        if (p.si_family != AF_INET) {
            return false;
        }
        std::memcpy(&out, &p.Ipv4, sizeof(sockaddr_in));
        outLen = sizeof(sockaddr_in);
        return true;
    }
    auto* sin6 = reinterpret_cast<sockaddr_in6*>(&out);
    if (p.si_family == AF_INET6) {
        *sin6 = p.Ipv6;
    } else {
        DWORD v6only = 1;
        int optLen = sizeof(v6only);
        getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&v6only), &optLen);
        if (v6only) {
            return false;
        }
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = p.Ipv4.sin_port;
        sin6->sin6_addr.u.Byte[10] = 0xFF;
        sin6->sin6_addr.u.Byte[11] = 0xFF;
        std::memcpy(&sin6->sin6_addr.u.Byte[12], &p.Ipv4.sin_addr, 4);
    }
    outLen = sizeof(sockaddr_in6);
    return true;
}

enum class ProxyOutcome {
    Direct,      // не через прокси (локальный адрес, не TCP) — вызвать оригинал
    Connected,   // соединение через прокси установлено
    Failed,      // ошибка выставлена
};

enum class DatagramRoute {
    Direct,   // как есть: локальный адрес, не UDP
    Relay,    // через реле прокси: адрес внутреннего сокета в shim
    Failed,   // ошибка выставлена
};

// UDP в правиле «прокси» (#46): локальные адреса — напрямую, остальное — через UDP ASSOCIATE
DatagramRoute RouteDatagram(SOCKET s, const sockaddr* to, int toLen, const wchar_t* api, const sockaddr*& shim,
                            int& shimLen)
{
    SOCKADDR_INET d{};
    int family = 0;
    int type = 0;
    if (!to || !ToInet(to, toLen, d) || !SocketInfo(s, family, type) || type != SOCK_DGRAM) {
        return DatagramRoute::Direct;
    }
    const SOCKADDR_INET target = Unmap(d);
    const auto host = g_fakeDns ? g_fakeIps.Lookup(target) : std::nullopt;
    if (!host) {
        if (FakeIpPool::InRange(target)) {
            Log(L"%ls → %ls: служебный адрес без имени — заблокировано", api, Describe(target).c_str());
            WSASetLastError(WSAEHOSTUNREACH);
            return DatagramRoute::Failed;
        }
        if (g_resolver.IsLocalDestination(target)) {
            return DatagramRoute::Direct;
        }
    }
    shim = UdpRelayRoute(s, family, to, toLen, target, host, shimLen);
    return shim ? DatagramRoute::Relay : DatagramRoute::Failed;
}

ProxyOutcome ConnectViaProxy(SOCKET s, const sockaddr* dest, int destLen, const wchar_t* api)
{
    SOCKADDR_INET d{};
    int family = 0;
    int type = 0;
    if (!ToInet(dest, destLen, d) || !SocketInfo(s, family, type)) {
        return ProxyOutcome::Direct;
    }
    const SOCKADDR_INET target = Unmap(d);
    if (type != SOCK_STREAM) {
        // Подключённый UDP-сокет — к внутреннему сокету реле; getpeername вернёт исходный адрес
        const sockaddr* shim = nullptr;
        int shimLen = 0;
        switch (RouteDatagram(s, dest, destLen, api, shim, shimLen)) {
        case DatagramRoute::Direct: return ProxyOutcome::Direct;
        case DatagramRoute::Failed: return ProxyOutcome::Failed;
        case DatagramRoute::Relay: break;
        }
        if (Real_connect(s, shim, shimLen) != 0) {
            return ProxyOutcome::Failed;
        }
        sockaddr_storage original{};
        std::memcpy(&original, dest, std::min<size_t>(static_cast<size_t>(destLen), sizeof(original)));
        AcquireSRWLockExclusive(&g_proxiedLock);
        g_proxied[s] = original;
        ReleaseSRWLockExclusive(&g_proxiedLock);
        return ProxyOutcome::Connected;
    }
    const auto host = g_fakeDns ? g_fakeIps.Lookup(target) : std::nullopt;
    if (!host && (FakeIpPool::InRange(target) || g_resolver.IsLocalDestination(target))) {
        if (FakeIpPool::InRange(target)) {
            Log(L"%ls → %ls: служебный адрес без имени — заблокировано", api, Describe(target).c_str());
            WSASetLastError(WSAEHOSTUNREACH);
            return ProxyOutcome::Failed;
        }
        return ProxyOutcome::Direct;
    }
    const std::wstring what = host ? Widen(*host) + L":" + std::to_wstring(ntohs(PortOf(target))) : Describe(target);

    sockaddr_storage proxy{};
    int proxyLen = 0;
    if (!ProxyAddressFor(s, family, proxy, proxyLen)) {
        Log(L"%ls → %ls: прокси %ls недоступен для сокета этого семейства — заблокировано", api, what.c_str(),
            FormatProxyAddress(*g_proxy).c_str());
        WSASetLastError(WSAEAFNOSUPPORT);
        return ProxyOutcome::Failed;
    }

    const ULONGLONG deadline = GetTickCount64() + 20000;
    const auto fail = [&](const wchar_t* stage) {
        const int err = WSAGetLastError() ? WSAGetLastError() : WSAECONNREFUSED;
        Log(L"%ls → %ls: прокси %ls: %ls (%d) — заблокировано", api, what.c_str(), FormatProxyAddress(*g_proxy).c_str(),
            stage, err);
        WSASetLastError(err);
        return ProxyOutcome::Failed;
    };
    if (Real_connect(s, reinterpret_cast<const sockaddr*>(&proxy), proxyLen) != 0) {
        const int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK || !WaitSocket(s, true, deadline)) {
            if (err != WSAEWOULDBLOCK) {
                WSASetLastError(err);
            }
            return fail(L"нет соединения с прокси");
        }
        int soError = 0;
        int len = sizeof(soError);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len);
        if (soError) {
            WSASetLastError(soError);
            return fail(L"нет соединения с прокси");
        }
    }

    char reply[262] = {};
    const Socks5Auth auth = Socks5Negotiate([&](std::string_view data) { return SendAll(s, data, deadline); },
                                            [&](char* out, size_t size) { return RecvExact(s, out, size, deadline); },
                                            g_credential ? &*g_credential : nullptr);
    if (auth != Socks5Auth::Ok) {
        if (auth != Socks5Auth::NoAnswer) {
            WSASetLastError(WSAECONNREFUSED);
        }
        return fail(Socks5AuthText(auth));
    }
    std::optional<std::string> request =
        host ? Socks5ConnectRequest(*host, PortOf(target)) : std::optional<std::string>(Socks5ConnectRequest(target));
    if (!request || !SendAll(s, *request, deadline) || !RecvExact(s, reply, 5, deadline)) {
        return fail(L"нет ответа на CONNECT");
    }
    const auto total = Socks5ReplyLength(std::string_view(reply, 5));
    if (!total || !RecvExact(s, reply + 5, *total - 5, deadline)) {
        WSASetLastError(WSAECONNREFUSED);
        return fail(L"неверный ответ прокси");
    }
    const auto code = static_cast<uint8_t>(reply[1]);
    if (code != 0) {
        WSASetLastError(Socks5ReplyToWsaError(code));
        return fail(Socks5ReplyText(code));
    }

    sockaddr_storage original{};
    std::memcpy(&original, dest, std::min<size_t>(static_cast<size_t>(destLen), sizeof(original)));
    AcquireSRWLockExclusive(&g_proxiedLock);
    g_proxied[s] = original;
    ReleaseSRWLockExclusive(&g_proxiedLock);
    Log(L"%ls → %ls через прокси %ls", api, what.c_str(), FormatProxyAddress(*g_proxy).c_str());
    return ProxyOutcome::Connected;
}

bool IsProxied(SOCKET s, sockaddr_storage* original = nullptr)
{
    AcquireSRWLockShared(&g_proxiedLock);
    const auto it = g_proxied.find(s);
    const bool found = it != g_proxied.end();
    if (found && original) {
        *original = it->second;
    }
    ReleaseSRWLockShared(&g_proxiedLock);
    return found;
}

// --- главное: подготовка сокета перед соединением / отправкой -------------------------------

// true — можно вызывать оригинал; false — вызов блокируется (код ошибки уже выставлен).
bool PrepareSocket(SOCKET s, const sockaddr* dest, int destLen, const wchar_t* api)
{
    SOCKADDR_INET d{};
    if (!ToInet(dest, destLen, d)) {
        return true;
    }

    const auto deferredPort = TakeDeferred(s);
    if (!deferredPort) {
        sockaddr_storage local{};
        int localLen = sizeof(local);
        if (Real_getsockname(s, reinterpret_cast<sockaddr*>(&local), &localLen) == 0) {
            // уже привязан (нами в bind() или самим процессом к конкретному адресу)
            std::optional<int> early;
            AcquireSRWLockShared(&g_deferredLock);
            if (auto it = g_earlyBound.find(s); it != g_earlyBound.end()) {
                early = it->second;
            }
            ReleaseSRWLockShared(&g_deferredLock);
            if (!early) {
                return true;
            }
            const SOCKADDR_INET t = Unmap(d);
            if (g_resolver.IsLocalDestination(t)) {
                return true;   // локальная сеть, multicast — напрямую, как и без правила
            }
            const wchar_t* kind = *early == SOCK_DGRAM ? L"UDP" : L"TCP";
            if (g_policy.UseDefaultRoute(t.si_family == AF_INET6)) {
                Log(L"%ls → %ls: %ls-сокет привязан к :: (getsockname до соединения) — маршрутом по умолчанию "
                    L"(default)", api, Describe(t).c_str(), kind);
                return true;
            }
            Log(L"%ls → %ls: заблокировано — %ls-сокет привязан к :: (getsockname до соединения), "
                L"к интерфейсу его не привязать", api, Describe(t).c_str(), kind);
            WSASetLastError(WSAENETUNREACH);
            return false;
        }
        if (WSAGetLastError() != WSAEINVAL) {
            return true;   // не сокет / закрыт — пусть оригинал вернёт свою ошибку
        }
    }

    const SOCKADDR_INET target = Unmap(d);
    if (g_resolver.IsLocalDestination(target)) {
        if (deferredPort) {
            BindDeferredAsRequested(s, *deferredPort);
        }
        return true;
    }

    sockaddr_storage src{};
    int srcLen = 0;
    if (!MakeBindAddress(d.si_family, target.si_family, deferredPort.value_or(0), src, srcLen)) {
        const wchar_t* family = target.si_family == AF_INET ? L"IPv4" : L"IPv6";
        if (g_policy.UseDefaultRoute(target.si_family == AF_INET6)) {
            Log(L"%ls → %ls: у интерфейса нет адреса %ls — маршрутом по умолчанию (default)",
                api, Describe(target).c_str(), family);
            if (deferredPort) {
                BindDeferredAsRequested(s, *deferredPort);
            }
            return true;
        }
        Log(L"%ls → %ls: заблокировано, у интерфейса нет адреса %ls", api, Describe(target).c_str(), family);
        WSASetLastError(WSAENETUNREACH);
        return false;
    }
    if (Real_bind(s, reinterpret_cast<const sockaddr*>(&src), srcLen) != 0) {
        const int err = WSAGetLastError();
        Log(L"%ls → %ls: bind на интерфейс не удался (%d), заблокировано", api, Describe(target).c_str(), err);
        WSASetLastError(err);
        return false;
    }

    SOCKADDR_INET bound{};
    ToInet(reinterpret_cast<const sockaddr*>(&src), srcLen, bound);
    Log(L"%ls → %ls через %ls", api, Describe(target).c_str(), FormatAddress(Unmap(bound)).c_str());
    return true;
}

// --- перехватчики --------------------------------------------------------------------------

int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen)
{
    if (g_proxy) {
        switch (ConnectViaProxy(s, name, namelen, L"connect")) {
        case ProxyOutcome::Direct: return Real_connect(s, name, namelen);
        case ProxyOutcome::Connected: return 0;
        case ProxyOutcome::Failed: return SOCKET_ERROR;
        }
    }
    if (!PrepareSocket(s, name, namelen, L"connect")) {
        return SOCKET_ERROR;
    }
    return Real_connect(s, name, namelen);
}

int WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF callerData,
                           LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
{
    if (g_proxy) {
        switch (ConnectViaProxy(s, name, namelen, L"WSAConnect")) {
        case ProxyOutcome::Direct: return Real_WSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
        case ProxyOutcome::Connected: return 0;
        case ProxyOutcome::Failed: return SOCKET_ERROR;
        }
    }
    if (!PrepareSocket(s, name, namelen, L"WSAConnect")) {
        return SOCKET_ERROR;
    }
    return Real_WSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
}

BOOL PASCAL Hook_ConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID sendBuffer,
                           DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped)
{
    if (g_proxy) {
        switch (ConnectViaProxy(s, name, namelen, L"ConnectEx")) {
        case ProxyOutcome::Direct: break;
        case ProxyOutcome::Failed: return FALSE;
        case ProxyOutcome::Connected: {
            // Соединение уже установлено; завершение ConnectEx (в порт завершения или событие
            // OVERLAPPED) даёт отправка его данных — пусть и нулевой длины — с тем же OVERLAPPED
            WSABUF buffer{sendDataLength, static_cast<CHAR*>(sendBuffer)};
            DWORD sent = 0;
            if (WSASend(s, &buffer, 1, &sent, 0, overlapped, nullptr) == 0) {
                if (bytesSent) {
                    *bytesSent = sent;
                }
                return TRUE;
            }
            return FALSE;   // WSA_IO_PENDING — как у ConnectEx
        }
        }
        return Real_ConnectEx(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
    }
    if (!PrepareSocket(s, name, namelen, L"ConnectEx")) {
        return FALSE;
    }
    return Real_ConnectEx(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

int WSAAPI Hook_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (g_proxy) {
        const sockaddr* shim = nullptr;
        int shimLen = 0;
        switch (RouteDatagram(s, to, tolen, L"sendto", shim, shimLen)) {
        case DatagramRoute::Direct: return Real_sendto(s, buf, len, flags, to, tolen);
        case DatagramRoute::Relay: return Real_sendto(s, buf, len, flags, shim, shimLen);
        case DatagramRoute::Failed: return SOCKET_ERROR;
        }
    }
    if (to && !PrepareSocket(s, to, tolen, L"sendto")) {
        return SOCKET_ERROR;
    }
    return Real_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags,
                          const sockaddr* to, int tolen, LPWSAOVERLAPPED overlapped,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_proxy) {
        const sockaddr* shim = nullptr;
        int shimLen = 0;
        switch (RouteDatagram(s, to, tolen, L"WSASendTo", shim, shimLen)) {
        case DatagramRoute::Direct: break;
        case DatagramRoute::Relay:
            return Real_WSASendTo(s, buffers, bufferCount, bytesSent, flags, shim, shimLen, overlapped, completion);
        case DatagramRoute::Failed: return SOCKET_ERROR;
        }
        return Real_WSASendTo(s, buffers, bufferCount, bytesSent, flags, to, tolen, overlapped, completion);
    }
    if (to && !PrepareSocket(s, to, tolen, L"WSASendTo")) {
        return SOCKET_ERROR;
    }
    return Real_WSASendTo(s, buffers, bufferCount, bytesSent, flags, to, tolen, overlapped, completion);
}

int WSAAPI Hook_WSASendMsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD bytesSent,
                           LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_proxy) {
        const sockaddr* shim = nullptr;
        int shimLen = 0;
        switch (msg && msg->name ? RouteDatagram(s, msg->name, msg->namelen, L"WSASendMsg", shim, shimLen)
                                 : DatagramRoute::Direct) {
        case DatagramRoute::Direct: break;
        case DatagramRoute::Failed: return SOCKET_ERROR;
        case DatagramRoute::Relay: {
            // Адрес назначения — на время вызова; Winsock копирует его при постановке операции
            LPSOCKADDR name = msg->name;
            const INT nameLen = msg->namelen;
            msg->name = const_cast<LPSOCKADDR>(shim);
            msg->namelen = shimLen;
            const int rc = Real_WSASendMsg(s, msg, flags, bytesSent, overlapped, completion);
            const int err = WSAGetLastError();
            msg->name = name;
            msg->namelen = nameLen;
            WSASetLastError(err);
            return rc;
        }
        }
        return Real_WSASendMsg(s, msg, flags, bytesSent, overlapped, completion);
    }
    if (msg && msg->name && !PrepareSocket(s, msg->name, msg->namelen, L"WSASendMsg")) {
        return SOCKET_ERROR;
    }
    return Real_WSASendMsg(s, msg, flags, bytesSent, overlapped, completion);
}

// --- приём UDP через прокси (#46): адрес отправителя — исходный, а не внутреннего сокета ---

// Адрес копируется через SEH: при завершении асинхронной операции программа могла уже
// освободить буфер адреса (если результат забрала мимо перехваченных функций)
bool CopyAddressIn(const sockaddr* from, const int* fromLen, sockaddr_storage& out, int& len)
{
    __try {
        len = *fromLen;
        if (len < static_cast<int>(sizeof(sockaddr_in)) || len > static_cast<int>(sizeof(out))) {
            return false;
        }
        std::memcpy(&out, from, static_cast<size_t>(len));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void CopyAddressOut(sockaddr* from, int* fromLen, const sockaddr_storage& in, int len)
{
    __try {
        std::memcpy(from, &in, static_cast<size_t>(len));
        *fromLen = len;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void RewriteFrom(sockaddr* from, int* fromLen)
{
    if (!from || !fromLen || !UdpRelayActive()) {
        return;
    }
    sockaddr_storage copy{};
    int len = 0;
    if (!CopyAddressIn(from, fromLen, copy, len)) {
        return;
    }
    const int before = len;
    sockaddr_storage original = copy;
    UdpRelayRewriteFrom(reinterpret_cast<sockaddr*>(&original), &len);
    if (len != before || std::memcmp(&original, &copy, static_cast<size_t>(len)) != 0) {
        CopyAddressOut(from, fromLen, original, len);
    }
}

// Асинхронный приём: куда записать адрес отправителя по завершении
struct PendingReceive {
    SOCKET s = INVALID_SOCKET;
    sockaddr* from = nullptr;
    int* fromLen = nullptr;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion = nullptr;
};
SRWLOCK g_pendingLock = SRWLOCK_INIT;
std::unordered_map<LPWSAOVERLAPPED, PendingReceive> g_pending;
std::atomic<size_t> g_pendingCount{0};

void TrackReceive(LPWSAOVERLAPPED overlapped, const PendingReceive& p)
{
    AcquireSRWLockExclusive(&g_pendingLock);
    if (g_pending.size() > 4096) {
        g_pending.clear();   // забытые операции (результат забран мимо перехватов)
    }
    g_pending[overlapped] = p;
    g_pendingCount = g_pending.size();
    ReleaseSRWLockExclusive(&g_pendingLock);
}

std::optional<PendingReceive> TakeReceive(LPOVERLAPPED overlapped)
{
    if (!overlapped || g_pendingCount.load(std::memory_order_relaxed) == 0) {
        return std::nullopt;
    }
    std::optional<PendingReceive> out;
    AcquireSRWLockExclusive(&g_pendingLock);
    if (const auto it = g_pending.find(overlapped); it != g_pending.end()) {
        out = it->second;
        g_pending.erase(it);
        g_pendingCount = g_pending.size();
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
    return out;
}

void DropReceives(SOCKET s)
{
    if (g_pendingCount.load(std::memory_order_relaxed) == 0) {
        return;
    }
    AcquireSRWLockExclusive(&g_pendingLock);
    std::erase_if(g_pending, [&](const auto& item) { return item.second.s == s; });
    g_pendingCount = g_pending.size();
    ReleaseSRWLockExclusive(&g_pendingLock);
}

void CompleteReceive(LPOVERLAPPED overlapped)
{
    if (const auto p = TakeReceive(overlapped)) {
        RewriteFrom(p->from, p->fromLen);
    }
}

void CALLBACK ReceiveCompleted(DWORD error, DWORD bytes, LPWSAOVERLAPPED overlapped, DWORD flags)
{
    const auto p = TakeReceive(overlapped);
    if (!p) {
        return;
    }
    if (error == 0) {
        RewriteFrom(p->from, p->fromLen);
    }
    if (p->completion) {
        p->completion(error, bytes, overlapped, flags);
    }
}

// Общая часть WSARecvFrom / WSARecvMsg: call — вызов оригинала с данной функцией завершения
template <typename Call>
int Receive(SOCKET s, sockaddr* from, int* fromLen, LPWSAOVERLAPPED overlapped,
            LPWSAOVERLAPPED_COMPLETION_ROUTINE completion, Call call)
{
    if (!g_proxy || !from || !fromLen) {
        return call(completion);
    }
    if (!overlapped) {
        const int rc = call(completion);
        if (rc == 0) {
            RewriteFrom(from, fromLen);
        }
        return rc;
    }
    TrackReceive(overlapped, {s, from, fromLen, completion});
    const int rc = call(completion ? &ReceiveCompleted : nullptr);
    const int err = WSAGetLastError();
    if (rc == 0) {
        RewriteFrom(from, fromLen);   // уже завершено; повторная подмена при завершении ничего не меняет
    } else if (err != WSA_IO_PENDING) {
        TakeReceive(overlapped);
    }
    WSASetLastError(err);
    return rc;
}

int WSAAPI Hook_recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    const int rc = Real_recvfrom(s, buf, len, flags, from, fromlen);
    if (rc != SOCKET_ERROR) {
        const int err = WSAGetLastError();
        RewriteFrom(from, fromlen);
        WSASetLastError(err);
    }
    return rc;
}

int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD received, LPDWORD flags,
                            sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED overlapped,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    return Receive(s, from, fromlen, overlapped, completion, [&](LPWSAOVERLAPPED_COMPLETION_ROUTINE routine) {
        return Real_WSARecvFrom(s, buffers, bufferCount, received, flags, from, fromlen, overlapped, routine);
    });
}

INT PASCAL Hook_WSARecvMsg(SOCKET s, LPWSAMSG msg, LPDWORD received, LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    return Receive(s, msg ? msg->name : nullptr, msg ? &msg->namelen : nullptr, overlapped, completion,
                   [&](LPWSAOVERLAPPED_COMPLETION_ROUTINE routine) {
                       return Real_WSARecvMsg(s, msg, received, overlapped, routine);
                   });
}

BOOL WSAAPI Hook_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED overlapped, LPDWORD transferred, BOOL wait,
                                        LPDWORD flags)
{
    const BOOL ok = Real_WSAGetOverlappedResult(s, overlapped, transferred, wait, flags);
    if (ok) {
        const int err = WSAGetLastError();
        CompleteReceive(overlapped);
        WSASetLastError(err);
    }
    return ok;
}

BOOL WINAPI Hook_GetOverlappedResult(HANDLE file, LPOVERLAPPED overlapped, LPDWORD transferred, BOOL wait)
{
    const BOOL ok = Real_GetOverlappedResult(file, overlapped, transferred, wait);
    if (ok && g_pendingCount.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        CompleteReceive(overlapped);
        SetLastError(err);
    }
    return ok;
}

BOOL WINAPI Hook_GetOverlappedResultEx(HANDLE file, LPOVERLAPPED overlapped, LPDWORD transferred, DWORD ms,
                                       BOOL alertable)
{
    const BOOL ok = Real_GetOverlappedResultEx(file, overlapped, transferred, ms, alertable);
    if (ok && g_pendingCount.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        CompleteReceive(overlapped);
        SetLastError(err);
    }
    return ok;
}

BOOL WINAPI Hook_GetQueuedCompletionStatus(HANDLE port, LPDWORD transferred, PULONG_PTR key,
                                           LPOVERLAPPED* overlapped, DWORD ms)
{
    const BOOL ok = Real_GetQueuedCompletionStatus(port, transferred, key, overlapped, ms);
    if (overlapped && *overlapped && g_pendingCount.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        if (ok) {
            CompleteReceive(*overlapped);
        } else {
            TakeReceive(*overlapped);
        }
        SetLastError(err);
    }
    return ok;
}

BOOL WINAPI Hook_GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed,
                                             DWORD ms, BOOL alertable)
{
    const BOOL ok = Real_GetQueuedCompletionStatusEx(port, entries, count, removed, ms, alertable);
    if (ok && removed && g_pendingCount.load(std::memory_order_relaxed) != 0) {
        const DWORD err = GetLastError();
        for (ULONG i = 0; i < *removed; ++i) {
            CompleteReceive(entries[i].lpOverlapped);
        }
        SetLastError(err);
    }
    return ok;
}

// bind() на "любой адрес" (0.0.0.0 / ::) подменяется адресом интерфейса — так, например,
// работает ConnectEx (.NET и др.) и UDP-сокеты, которые сначала привязываются, а потом шлют.
int WSAAPI Hook_bind(SOCKET s, const sockaddr* name, int namelen)
{
    SOCKADDR_INET a{};
    if (g_proxy || !ToInet(name, namelen, a) || !IsZeroAddress(a)) {   // прокси: привязка не нужна
        return Real_bind(s, name, namelen);
    }

    int type = 0;
    int typeLen = sizeof(type);
    getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &typeLen);
    if (type == SOCK_STREAM && PortOf(a) != 0) {
        return Real_bind(s, name, namelen);   // TCP на фиксированном порту — похоже на сервер
    }

    if (a.si_family == AF_INET6) {
        DWORD v6only = 1;
        int optLen = sizeof(v6only);
        getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&v6only), &optLen);
        if (!v6only) {
            AcquireSRWLockExclusive(&g_deferredLock);
            g_deferred[s] = PortOf(a);
            ReleaseSRWLockExclusive(&g_deferredLock);
            return 0;
        }
    }

    sockaddr_storage src{};
    int srcLen = 0;
    if (!MakeBindAddress(a.si_family, a.si_family, PortOf(a), src, srcLen)) {
        if (g_policy.UseDefaultRoute(a.si_family == AF_INET6)) {
            return Real_bind(s, name, namelen);   // как просил процесс (default)
        }
        Log(L"bind %ls: заблокировано, у интерфейса нет адреса %ls",
            Describe(a).c_str(), a.si_family == AF_INET ? L"IPv4" : L"IPv6");
        WSASetLastError(WSAEADDRNOTAVAIL);
        return SOCKET_ERROR;
    }
    return Real_bind(s, reinterpret_cast<const sockaddr*>(&src), srcLen);
}

int WSAAPI Hook_listen(SOCKET s, int backlog)
{
    if (const auto port = TakeDeferred(s)) {
        BindDeferredAsRequested(s, *port);
    }
    return Real_listen(s, backlog);
}

int WSAAPI Hook_getsockname(SOCKET s, sockaddr* name, int* namelen)
{
    if (const auto port = TakeDeferred(s)) {
        // Процессу нужен локальный адрес до соединения — привязываем как просили
        int type = 0;
        int typeLen = sizeof(type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &typeLen);
        Log(L"getsockname до соединения на двухстековом %ls-сокете (порт %u): привязка к :: — дальше с него "
            L"только локальная сеть",
            type == SOCK_DGRAM ? L"UDP" : L"TCP", static_cast<unsigned>(ntohs(*port)));
        BindDeferredAsRequested(s, *port);
        AcquireSRWLockExclusive(&g_deferredLock);
        g_earlyBound[s] = type;
        ReleaseSRWLockExclusive(&g_deferredLock);
    }
    return Real_getsockname(s, name, namelen);
}

int WSAAPI Hook_getpeername(SOCKET s, sockaddr* name, int* namelen)
{
    // Соединение через прокси: программе — тот адрес, с которым она соединялась
    sockaddr_storage original{};
    if (name && namelen && IsProxied(s, &original)) {
        const int len = original.ss_family == AF_INET6 ? static_cast<int>(sizeof(sockaddr_in6))
                                                       : static_cast<int>(sizeof(sockaddr_in));
        if (*namelen < len) {
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }
        std::memcpy(name, &original, static_cast<size_t>(len));
        *namelen = len;
        return 0;
    }
    return Real_getpeername(s, name, namelen);
}

int WSAAPI Hook_setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen)
{
    // После «ConnectEx» через прокси сокет соединён обычным connect — контекст уже обновлён
    if (level == SOL_SOCKET && optname == SO_UPDATE_CONNECT_CONTEXT && IsProxied(s)) {
        return 0;
    }
    return Real_setsockopt(s, level, optname, optval, optlen);
}

int WSAAPI Hook_closesocket(SOCKET s)
{
    TakeDeferred(s);
    AcquireSRWLockExclusive(&g_deferredLock);
    g_earlyBound.erase(s);
    ReleaseSRWLockExclusive(&g_deferredLock);
    if (g_proxy) {
        AcquireSRWLockExclusive(&g_proxiedLock);
        g_proxied.erase(s);
        ReleaseSRWLockExclusive(&g_proxiedLock);
        UdpRelayClose(s);
        DropReceives(s);
    }
    return Real_closesocket(s);
}

// ConnectEx — не экспорт, а указатель из WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER).
// Подменяем возвращаемый указатель на свой перехватчик.
int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize,
                         LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    const int rc = Real_WSAIoctl(s, code, inBuffer, inSize, outBuffer, outSize, bytesReturned, overlapped, completion);
    if (rc != 0 || code != SIO_GET_EXTENSION_FUNCTION_POINTER || !inBuffer || inSize < sizeof(GUID)
        || !outBuffer || outSize < sizeof(LPFN_CONNECTEX)) {
        return rc;
    }
    static const GUID connectExId = WSAID_CONNECTEX;
    static const GUID recvMsgId = WSAID_WSARECVMSG;
    if (g_proxy && std::memcmp(inBuffer, &recvMsgId, sizeof(GUID)) == 0) {
        auto* fn = static_cast<LPFN_WSARECVMSG*>(outBuffer);
        AcquireSRWLockExclusive(&g_connectExLock);
        if (!Real_WSARecvMsg) {
            Real_WSARecvMsg = *fn;
        }
        if (*fn == Real_WSARecvMsg) {
            *fn = &Hook_WSARecvMsg;
        }
        ReleaseSRWLockExclusive(&g_connectExLock);
        return rc;
    }
    if (std::memcmp(inBuffer, &connectExId, sizeof(GUID)) != 0) {
        return rc;
    }

    auto* fn = static_cast<LPFN_CONNECTEX*>(outBuffer);
    AcquireSRWLockExclusive(&g_connectExLock);
    if (!Real_ConnectEx) {
        Real_ConnectEx = *fn;
    }
    if (*fn == Real_ConnectEx) {
        *fn = &Hook_ConnectEx;
    } else if (*fn != &Hook_ConnectEx) {
        Log(L"ConnectEx другого провайдера не перехвачен");
    }
    ReleaseSRWLockExclusive(&g_connectExLock);
    return rc;
}

template <typename T>
bool HookApi(const char* name, T* detour, T** original, const wchar_t* module = L"ws2_32")
{
    const MH_STATUS st = MH_CreateHookApi(module, name, reinterpret_cast<LPVOID>(detour),
                                          reinterpret_cast<LPVOID*>(original));
    if (st != MH_OK) {
        Log(L"не удалось перехватить %hs: %hs", name, MH_StatusToString(st));
        return false;
    }
    return true;
}

} // namespace

void Install()
{
    LogInit();

    wchar_t guid[64] = {};
    wchar_t proxy[80] = {};
    const DWORD proxyLen = GetEnvironmentVariableW(kEnvProxy, proxy, static_cast<DWORD>(std::size(proxy)));
    if (proxyLen > 0 && proxyLen < std::size(proxy)) {
        g_proxy = ParseProxyAddress(proxy);
        if (!g_proxy) {
            Log(L"неверный адрес прокси в %ls: %ls", kEnvProxy, proxy);
            return;
        }
        // Резолвер без интерфейса: нужен только для локальных подсетей. Логин и пароль прокси
        // (если заданы) — из диспетчера учётных данных этого пользователя, не из окружения
        g_credential = ReadProxyCredential(*g_proxy);
    } else if (GetEnvironmentVariableW(kEnvAdapter, guid, static_cast<DWORD>(std::size(guid))) == 0) {
        return;   // правило не задано — DLL ничего не делает
    } else if (!g_resolver.Init(guid)) {
        Log(L"неверный GUID интерфейса в %ls: %ls", kEnvAdapter, guid);
        return;
    }

    g_policy = PolicyFromEnvironment();

    RuleConfig config;
    config.adapterGuid = guid;
    if (g_proxy) {
        config.proxy = proxy;
    }
    wchar_t buffer[MAX_PATH] = {};
    if (GetEnvironmentVariableW(kEnvLog, buffer, MAX_PATH) != 0) {
        config.logPath = buffer;
    }
    if (GetEnvironmentVariableW(kEnvChildren, buffer, MAX_PATH) != 0) {
        config.includeChildren = std::wstring_view(buffer) != L"0";
    }

    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);

    if (MH_Initialize() != MH_OK) {
        Log(L"MH_Initialize не удался");
        return;
    }

    HookApi("connect", &Hook_connect, &Real_connect);
    HookApi("WSAConnect", &Hook_WSAConnect, &Real_WSAConnect);
    HookApi("bind", &Hook_bind, &Real_bind);
    HookApi("sendto", &Hook_sendto, &Real_sendto);
    HookApi("WSASendTo", &Hook_WSASendTo, &Real_WSASendTo);
    HookApi("WSASendMsg", &Hook_WSASendMsg, &Real_WSASendMsg);
    HookApi("WSAIoctl", &Hook_WSAIoctl, &Real_WSAIoctl);
    HookApi("getsockname", &Hook_getsockname, &Real_getsockname);
    HookApi("listen", &Hook_listen, &Real_listen);
    HookApi("closesocket", &Hook_closesocket, &Real_closesocket);
    if (g_proxy) {
        HookApi("getpeername", &Hook_getpeername, &Real_getpeername);
        HookApi("setsockopt", &Hook_setsockopt, &Real_setsockopt);
        // UDP через прокси (#46)
        HookApi("recvfrom", &Hook_recvfrom, &Real_recvfrom);
        HookApi("WSARecvFrom", &Hook_WSARecvFrom, &Real_WSARecvFrom);
        HookApi("WSAGetOverlappedResult", &Hook_WSAGetOverlappedResult, &Real_WSAGetOverlappedResult);
        HookApi("GetOverlappedResult", &Hook_GetOverlappedResult, &Real_GetOverlappedResult, L"kernelbase");
        HookApi("GetOverlappedResultEx", &Hook_GetOverlappedResultEx, &Real_GetOverlappedResultEx, L"kernelbase");
        HookApi("GetQueuedCompletionStatus", &Hook_GetQueuedCompletionStatus, &Real_GetQueuedCompletionStatus,
                L"kernelbase");
        HookApi("GetQueuedCompletionStatusEx", &Hook_GetQueuedCompletionStatusEx, &Real_GetQueuedCompletionStatusEx,
                L"kernelbase");
        UdpRelayApi api;
        api.connect = Real_connect;
        api.sendto = Real_sendto;
        api.recvfrom = Real_recvfrom;
        api.closesocket = Real_closesocket;
        api.getsockname = Real_getsockname;
        UdpRelayInit(*g_proxy, g_credential ? &*g_credential : nullptr, api);
    }
    g_fakeDns = CreateDnsHooks(g_resolver, g_policy, g_proxy ? &g_fakeIps : nullptr);
    CreateProcessHooks(config);

    const MH_STATUS st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK) {
        Log(L"MH_EnableHook: %hs", MH_StatusToString(st));
        return;
    }
    g_installed = true;
    if (g_proxy) {
        Log(L"активен в %ls, прокси SOCKS5 %ls%ls, имена разрешает прокси: %ls", exe,
            FormatProxyAddress(*g_proxy).c_str(), g_credential ? L" (с логином и паролем)" : L"",
            g_fakeDns ? L"да" : L"нет");
    } else {
        Log(L"активен в %ls, интерфейс %ls, без интерфейса: %ls", exe, guid,
            g_policy.onUnavailable == OnUnavailable::Default ? L"default" : L"block");
    }
}

void Uninstall()
{
    if (!g_installed) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_installed = false;
}

} // namespace approute::hook
