#include "UdpRelay.h"
#include "Log.h"

#include "core/Socks5.h"
#include "core/Util.h"

#include <mstcpip.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

namespace approute::hook {

namespace {

constexpr size_t kMaxAssociations = 64;
constexpr DWORD kHandshakeMs = 10000;
constexpr size_t kMaxHeader = 4 + 1 + 255 + 2;

struct Association {
    SOCKET app = INVALID_SOCKET;
    std::string key;                    // назначение: адрес или имя с портом
    std::wstring what;                  // для журнала
    sockaddr_storage original{};        // назначение, как его задала программа
    int originalLen = 0;
    std::string header;                 // заголовок SOCKS5 для датаграмм на это назначение

    SOCKET shim = INVALID_SOCKET;       // внутренний сокет на loopback, к нему шлёт программа
    USHORT shimPort = 0;                // сетевой порядок
    sockaddr_storage shimForApp{};      // адрес внутреннего сокета для семейства сокета программы
    int shimForAppLen = 0;
    sockaddr_storage appAddr{};         // откуда пишет программа (первая принятая датаграмма)
    int appAddrLen = 0;

    SOCKET control = INVALID_SOCKET;    // управляющее TCP-соединение с прокси
    SOCKET upstream = INVALID_SOCKET;   // сокет к реле
    sockaddr_storage relay{};
    int relayLen = 0;

    bool closing = false;
};

UdpRelayApi g_api;
SOCKADDR_INET g_proxy{};
const ProxyCredential* g_credential = nullptr;
SRWLOCK g_lock = SRWLOCK_INIT;
std::vector<std::unique_ptr<Association>> g_assocs;
std::atomic<bool> g_active{false};
bool g_threadStarted = false;
SOCKET g_wake = INVALID_SOCKET;
sockaddr_in g_wakeAddr{};

void CloseSocket(SOCKET& s)
{
    if (s != INVALID_SOCKET) {
        g_api.closesocket(s);
        s = INVALID_SOCKET;
    }
}

int AddressLength(int family)
{
    return family == AF_INET6 ? static_cast<int>(sizeof(sockaddr_in6)) : static_cast<int>(sizeof(sockaddr_in));
}

bool IsLoopback(const sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
        return reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.S_un.S_un_b.s_b1 == 127;
    }
    if (sa->sa_family == AF_INET6) {
        const auto& a = reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(&a) || (IN6_IS_ADDR_V4MAPPED(&a) && a.u.Byte[12] == 127);
    }
    return false;
}

USHORT PortOf(const sockaddr* sa)
{
    return sa->sa_family == AF_INET6 ? reinterpret_cast<const sockaddr_in6*>(sa)->sin6_port
                                     : reinterpret_cast<const sockaddr_in*>(sa)->sin_port;
}

// Ошибки ICMP «порт недоступен» не должны ломать приём на наших UDP-сокетах
void DisableConnReset(SOCKET s)
{
    BOOL off = FALSE;
    DWORD bytes = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr);
}

bool WaitWritable(SOCKET s, DWORD ms)
{
    fd_set write;
    fd_set errors;
    FD_ZERO(&write);
    FD_ZERO(&errors);
    FD_SET(s, &write);
    FD_SET(s, &errors);
    timeval tv{static_cast<long>(ms / 1000), static_cast<long>((ms % 1000) * 1000)};
    return select(0, nullptr, &write, &errors, &tv) > 0 && FD_ISSET(s, &write);
}

bool SendAll(SOCKET s, std::string_view data)
{
    while (!data.empty()) {
        const int n = send(s, data.data(), static_cast<int>(data.size()), 0);
        if (n <= 0) {
            return false;
        }
        data.remove_prefix(static_cast<size_t>(n));
    }
    return true;
}

bool RecvExact(SOCKET s, char* out, size_t size)
{
    size_t got = 0;
    while (got < size) {
        const int n = recv(s, out + got, static_cast<int>(size - got), 0);
        if (n <= 0) {
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

// Управляющее соединение и реле: UDP ASSOCIATE. Ошибка — описание в error, код в WSA.
bool Associate(Association& a, const wchar_t*& error)
{
    const int family = g_proxy.si_family;
    a.control = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (a.control == INVALID_SOCKET) {
        error = L"нет сокета для прокси";
        return false;
    }
    u_long nonBlocking = 1;
    ioctlsocket(a.control, FIONBIO, &nonBlocking);
    const int rc = g_api.connect(a.control, reinterpret_cast<const sockaddr*>(&g_proxy), AddressLength(family));
    if (rc != 0 && (WSAGetLastError() != WSAEWOULDBLOCK || !WaitWritable(a.control, kHandshakeMs))) {
        error = L"нет соединения с прокси";
        return false;
    }
    nonBlocking = 0;
    ioctlsocket(a.control, FIONBIO, &nonBlocking);
    const DWORD timeout = kHandshakeMs;
    setsockopt(a.control, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(a.control, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    char reply[kMaxHeader] = {};
    const Socks5Auth auth = Socks5Negotiate([&](std::string_view data) { return SendAll(a.control, data); },
                                            [&](char* out, size_t size) { return RecvExact(a.control, out, size); },
                                            g_credential);
    if (auth != Socks5Auth::Ok) {
        if (auth != Socks5Auth::NoAnswer) {
            WSASetLastError(WSAECONNREFUSED);
        }
        error = Socks5AuthText(auth);
        return false;
    }
    if (!SendAll(a.control, Socks5UdpAssociateRequest()) || !RecvExact(a.control, reply, 5)) {
        error = L"нет ответа на UDP ASSOCIATE";
        return false;
    }
    const auto total = Socks5ReplyLength(std::string_view(reply, 5));
    if (!total || !RecvExact(a.control, reply + 5, *total - 5)) {
        WSASetLastError(WSAECONNREFUSED);
        error = L"неверный ответ прокси";
        return false;
    }
    const auto code = static_cast<uint8_t>(reply[1]);
    if (code != 0) {
        WSASetLastError(Socks5ReplyToWsaError(code));
        error = code == 0x07 ? L"прокси не поддерживает UDP (UDP ASSOCIATE отклонён)" : Socks5ReplyText(code);
        return false;
    }
    auto relay = Socks5ReplyAddress(std::string_view(reply, *total));
    if (!relay) {
        WSASetLastError(WSAECONNREFUSED);
        error = L"прокси не сообщил адрес реле";
        return false;
    }
    if (IsZeroAddress(*relay)) {
        // 0.0.0.0 — реле на том же адресе, что и прокси
        const USHORT port = relay->si_family == AF_INET6 ? relay->Ipv6.sin6_port : relay->Ipv4.sin_port;
        *relay = g_proxy;
        (relay->si_family == AF_INET6 ? relay->Ipv6.sin6_port : relay->Ipv4.sin_port) = port;
    }
    a.relayLen = AddressLength(relay->si_family);
    std::memcpy(&a.relay, &*relay, static_cast<size_t>(a.relayLen));

    a.upstream = socket(relay->si_family, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_storage any{};
    any.ss_family = relay->si_family;
    if (a.upstream == INVALID_SOCKET ||
        bind(a.upstream, reinterpret_cast<const sockaddr*>(&any), AddressLength(relay->si_family)) != 0) {
        error = L"нет сокета для реле";
        return false;
    }
    DisableConnReset(a.upstream);
    return true;
}

// Внутренний сокет на loopback и его адрес для сокета программы
bool CreateShim(Association& a, int socketFamily, bool v6only)
{
    const int family = socketFamily == AF_INET6 && v6only ? AF_INET6 : AF_INET;
    a.shim = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (a.shim == INVALID_SOCKET) {
        return false;
    }
    sockaddr_storage local{};
    local.ss_family = static_cast<ADDRESS_FAMILY>(family);
    if (family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(&local)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        reinterpret_cast<sockaddr_in6*>(&local)->sin6_addr = in6addr_loopback;
    }
    int len = AddressLength(family);
    if (bind(a.shim, reinterpret_cast<const sockaddr*>(&local), len) != 0 ||
        g_api.getsockname(a.shim, reinterpret_cast<sockaddr*>(&local), &len) != 0) {
        return false;
    }
    DisableConnReset(a.shim);
    a.shimPort = PortOf(reinterpret_cast<const sockaddr*>(&local));

    a.shimForApp = {};
    if (socketFamily == AF_INET) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&a.shimForApp);
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin->sin_port = a.shimPort;
        a.shimForAppLen = sizeof(sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&a.shimForApp);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = a.shimPort;
        if (v6only) {
            sin6->sin6_addr = in6addr_loopback;
        } else {
            sin6->sin6_addr.u.Byte[10] = 0xFF;   // ::ffff:127.0.0.1
            sin6->sin6_addr.u.Byte[11] = 0xFF;
            sin6->sin6_addr.u.Byte[12] = 127;
            sin6->sin6_addr.u.Byte[15] = 1;
        }
        a.shimForAppLen = sizeof(sockaddr_in6);
    }
    return true;
}

void Release(Association& a)
{
    CloseSocket(a.shim);
    CloseSocket(a.control);
    CloseSocket(a.upstream);
}

void Wake()
{
    if (g_wake != INVALID_SOCKET) {
        const char b = 0;
        g_api.sendto(g_wake, &b, 1, 0, reinterpret_cast<const sockaddr*>(&g_wakeAddr), sizeof(g_wakeAddr));
    }
}

// Датаграмма программы → реле
void FromApp(Association& a, std::vector<char>& buffer)
{
    sockaddr_storage from{};
    int fromLen = sizeof(from);
    const size_t headerLen = a.header.size();
    const int n = g_api.recvfrom(a.shim, buffer.data() + headerLen, static_cast<int>(buffer.size() - headerLen), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (n < 0) {
        return;
    }
    // Только с loopback и с порта сокета программы: внутренний сокет не открыт для других программ
    sockaddr_storage appLocal{};
    int appLocalLen = sizeof(appLocal);
    if (!IsLoopback(reinterpret_cast<const sockaddr*>(&from)) ||
        g_api.getsockname(a.app, reinterpret_cast<sockaddr*>(&appLocal), &appLocalLen) != 0 ||
        PortOf(reinterpret_cast<const sockaddr*>(&appLocal)) != PortOf(reinterpret_cast<const sockaddr*>(&from))) {
        return;
    }
    a.appAddr = from;
    a.appAddrLen = fromLen;
    if (a.control == INVALID_SOCKET) {
        // Прокси закрыл ассоциацию — открыть заново
        const wchar_t* error = L"";
        if (!Associate(a, error)) {
            Log(L"UDP → %ls: прокси: %ls (%d) — датаграмма отброшена", a.what.c_str(), error, WSAGetLastError());
            CloseSocket(a.control);
            CloseSocket(a.upstream);
            return;
        }
        Log(L"UDP → %ls: ассоциация с прокси восстановлена", a.what.c_str());
    }
    std::memcpy(buffer.data(), a.header.data(), headerLen);
    g_api.sendto(a.upstream, buffer.data(), static_cast<int>(headerLen) + n, 0,
                 reinterpret_cast<const sockaddr*>(&a.relay), a.relayLen);
}

// Датаграмма реле → программе
void FromRelay(Association& a, std::vector<char>& buffer)
{
    sockaddr_storage from{};
    int fromLen = sizeof(from);
    const int n = g_api.recvfrom(a.upstream, buffer.data(), static_cast<int>(buffer.size()), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (n <= 0 || a.appAddrLen == 0 || PortOf(reinterpret_cast<const sockaddr*>(&from)) !=
                                           PortOf(reinterpret_cast<const sockaddr*>(&a.relay))) {
        return;
    }
    const auto headerLen = Socks5UdpHeaderLength(std::string_view(buffer.data(), static_cast<size_t>(n)));
    if (!headerLen) {
        return;
    }
    g_api.sendto(a.shim, buffer.data() + *headerLen, n - static_cast<int>(*headerLen), 0,
                 reinterpret_cast<const sockaddr*>(&a.appAddr), a.appAddrLen);
}

void ControlEvent(Association& a)
{
    char b[64];
    const int n = recv(a.control, b, sizeof(b), 0);
    if (n > 0) {
        return;   // прокси ничего не должен присылать — игнорируем
    }
    Log(L"UDP → %ls: прокси закрыл управляющее соединение", a.what.c_str());
    CloseSocket(a.control);
    CloseSocket(a.upstream);
}

DWORD WINAPI RelayThread(void*)
{
    std::vector<char> buffer(65536 + kMaxHeader);
    std::vector<WSAPOLLFD> fds;
    struct Owner {
        Association* a;
        int kind;   // 0 — внутренний, 1 — реле, 2 — управляющее
    };
    std::vector<Owner> owners;
    for (;;) {
        fds.clear();
        owners.clear();
        fds.push_back({g_wake, POLLRDNORM, 0});
        owners.push_back({nullptr, -1});
        AcquireSRWLockExclusive(&g_lock);
        for (auto it = g_assocs.begin(); it != g_assocs.end();) {
            if ((*it)->closing) {
                Release(**it);
                it = g_assocs.erase(it);
                continue;
            }
            Association* a = it->get();
            fds.push_back({a->shim, POLLRDNORM, 0});
            owners.push_back({a, 0});
            if (a->upstream != INVALID_SOCKET) {
                fds.push_back({a->upstream, POLLRDNORM, 0});
                owners.push_back({a, 1});
            }
            if (a->control != INVALID_SOCKET) {
                fds.push_back({a->control, POLLRDNORM, 0});
                owners.push_back({a, 2});
            }
            ++it;
        }
        ReleaseSRWLockExclusive(&g_lock);

        if (WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), -1) <= 0) {
            Sleep(10);
            continue;
        }
        // Ассоциации удаляет только этот поток — указатели действительны до следующего круга
        for (size_t i = 0; i < fds.size(); ++i) {
            if (!fds[i].revents) {
                continue;
            }
            const Owner& o = owners[i];
            if (!o.a) {
                char drain[16];
                g_api.recvfrom(g_wake, drain, sizeof(drain), 0, nullptr, nullptr);
                continue;
            }
            if (o.a->closing) {
                continue;
            }
            switch (o.kind) {
            case 0: FromApp(*o.a, buffer); break;
            case 1: if (o.a->upstream != INVALID_SOCKET) FromRelay(*o.a, buffer); break;
            case 2: if (o.a->control != INVALID_SOCKET) ControlEvent(*o.a); break;
            }
        }
    }
}

bool StartThread()
{
    if (g_threadStarted) {
        return true;
    }
    g_wake = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    g_wakeAddr = {};
    g_wakeAddr.sin_family = AF_INET;
    g_wakeAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int len = sizeof(g_wakeAddr);
    if (g_wake == INVALID_SOCKET || bind(g_wake, reinterpret_cast<const sockaddr*>(&g_wakeAddr), len) != 0 ||
        g_api.getsockname(g_wake, reinterpret_cast<sockaddr*>(&g_wakeAddr), &len) != 0) {
        CloseSocket(g_wake);
        return false;
    }
    DisableConnReset(g_wake);
    HANDLE thread = CreateThread(nullptr, 0, &RelayThread, nullptr, 0, nullptr);
    if (!thread) {
        CloseSocket(g_wake);
        return false;
    }
    CloseHandle(thread);
    g_threadStarted = true;
    return true;
}

std::string KeyOf(const SOCKADDR_INET& target, const std::optional<std::string>& host)
{
    if (host) {
        return "n" + *host + ":" + std::to_string(target.si_family == AF_INET6 ? target.Ipv6.sin6_port
                                                                             : target.Ipv4.sin_port);
    }
    const auto* p = reinterpret_cast<const char*>(&target);
    return "a" + std::string(p, target.si_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
}

} // namespace

void UdpRelayInit(const SOCKADDR_INET& proxy, const ProxyCredential* credential, const UdpRelayApi& api)
{
    g_proxy = proxy;
    g_credential = credential;
    g_api = api;
}

bool UdpRelayActive()
{
    return g_active.load(std::memory_order_relaxed);
}

const sockaddr* UdpRelayRoute(SOCKET s, int socketFamily, const sockaddr* original, int originalLen,
                              const SOCKADDR_INET& target, const std::optional<std::string>& host, int& shimLen)
{
    const std::string key = KeyOf(target, host);
    AcquireSRWLockShared(&g_lock);
    for (const auto& a : g_assocs) {
        if (a->app == s && !a->closing && a->key == key) {
            shimLen = a->shimForAppLen;
            const auto* shim = reinterpret_cast<const sockaddr*>(&a->shimForApp);
            ReleaseSRWLockShared(&g_lock);
            return shim;
        }
    }
    const size_t count = g_assocs.size();
    ReleaseSRWLockShared(&g_lock);

    const std::wstring port = std::to_wstring(ntohs(target.si_family == AF_INET6 ? target.Ipv6.sin6_port
                                                                              : target.Ipv4.sin_port));
    auto a = std::make_unique<Association>();
    a->app = s;
    a->key = key;
    a->what = host ? std::wstring(host->begin(), host->end()) + L":" + port
                   : (target.si_family == AF_INET6 ? L"[" + FormatAddress(target) + L"]:" : FormatAddress(target) + L":") +
                         port;
    if (count >= kMaxAssociations) {
        Log(L"UDP → %ls: слишком много назначений UDP через прокси — заблокировано", a->what.c_str());
        WSASetLastError(WSAENOBUFS);
        return nullptr;
    }
    a->originalLen = std::min<int>(originalLen, static_cast<int>(sizeof(a->original)));
    std::memcpy(&a->original, original, static_cast<size_t>(a->originalLen));
    if (host) {
        const auto header = Socks5UdpHeader(*host, target.si_family == AF_INET6 ? target.Ipv6.sin6_port
                                                                              : target.Ipv4.sin_port);
        if (!header) {
            WSASetLastError(WSAEHOSTUNREACH);
            return nullptr;
        }
        a->header = *header;
    } else {
        a->header = Socks5UdpHeader(target);
    }

    DWORD v6only = 1;
    int optLen = sizeof(v6only);
    if (socketFamily == AF_INET6) {
        getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&v6only), &optLen);
    }
    const wchar_t* error = L"";
    if (!CreateShim(*a, socketFamily, v6only != 0)) {
        error = L"нет внутреннего сокета";
    } else if (!Associate(*a, error)) {
        // error заполнен
    } else {
        AcquireSRWLockExclusive(&g_lock);
        const bool started = StartThread();
        if (started) {
            shimLen = a->shimForAppLen;
            const auto* shim = reinterpret_cast<const sockaddr*>(&a->shimForApp);
            Log(L"UDP → %ls через прокси %ls (реле %ls)", a->what.c_str(), FormatProxyAddress(g_proxy).c_str(),
                FormatProxyAddress(*reinterpret_cast<const SOCKADDR_INET*>(&a->relay)).c_str());
            g_assocs.push_back(std::move(a));
            g_active = true;
            ReleaseSRWLockExclusive(&g_lock);
            Wake();
            return shim;
        }
        ReleaseSRWLockExclusive(&g_lock);
        error = L"нет потока реле";
    }
    const int err = WSAGetLastError() ? WSAGetLastError() : WSAECONNREFUSED;
    Log(L"UDP → %ls: прокси %ls: %ls (%d) — заблокировано", a->what.c_str(), FormatProxyAddress(g_proxy).c_str(),
        error, err);
    Release(*a);
    WSASetLastError(err);
    return nullptr;
}

void UdpRelayRewriteFrom(sockaddr* from, int* fromLen)
{
    if (!from || !fromLen || !UdpRelayActive() || *fromLen < static_cast<int>(sizeof(sockaddr_in)) ||
        (from->sa_family != AF_INET && from->sa_family != AF_INET6) || !IsLoopback(from)) {
        return;
    }
    const USHORT port = PortOf(from);
    AcquireSRWLockShared(&g_lock);
    for (const auto& a : g_assocs) {
        if (a->shimPort == port && a->originalLen <= *fromLen) {
            std::memcpy(from, &a->original, static_cast<size_t>(a->originalLen));
            *fromLen = a->originalLen;
            break;
        }
    }
    ReleaseSRWLockShared(&g_lock);
}

void UdpRelayClose(SOCKET s)
{
    if (!UdpRelayActive()) {
        return;
    }
    bool any = false;
    AcquireSRWLockExclusive(&g_lock);
    for (auto& a : g_assocs) {
        if (a->app == s && !a->closing) {
            a->closing = true;
            any = true;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (any) {
        Wake();
    }
}

} // namespace approute::hook
