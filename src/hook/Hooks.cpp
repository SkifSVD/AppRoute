// Перехват Winsock: перед соединением/отправкой сокет привязывается к IP выбранного интерфейса.
// Windows (strong host model) отправляет пакеты привязанного сокета только маршрутами этого
// интерфейса, поэтому трафик уходит через него, какой бы интерфейс ни был основным.
//
// Политика при недоступном интерфейсе пока одна — block (WSAENETUNREACH); настройка — issue #9.

#include "Hooks.h"
#include "AdapterResolver.h"
#include "DnsHooks.h"
#include "Log.h"
#include "ProcessHooks.h"

#include "core/Process.h"
#include "core/Util.h"

#include <MinHook.h>
#include <mswsock.h>

#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace approute::hook {

namespace {

AdapterResolver g_resolver;
bool g_installed = false;

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

SRWLOCK g_connectExLock = SRWLOCK_INIT;
LPFN_CONNECTEX Real_ConnectEx = nullptr;

// Двухстековые IPv6-сокеты, привязанные к "::" — настоящий bind откладывается до первого
// соединения, когда станет известно семейство адреса назначения. Значение — порт (сетевой порядок).
SRWLOCK g_deferredLock = SRWLOCK_INIT;
std::unordered_map<SOCKET, USHORT> g_deferred;

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
            return true;   // уже привязан (нами в bind() или самим процессом к конкретному адресу)
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
        Log(L"%ls → %ls: заблокировано, у интерфейса нет адреса %ls",
            api, Describe(target).c_str(), target.si_family == AF_INET ? L"IPv4" : L"IPv6");
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
    if (!PrepareSocket(s, name, namelen, L"connect")) {
        return SOCKET_ERROR;
    }
    return Real_connect(s, name, namelen);
}

int WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF callerData,
                           LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
{
    if (!PrepareSocket(s, name, namelen, L"WSAConnect")) {
        return SOCKET_ERROR;
    }
    return Real_WSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
}

BOOL PASCAL Hook_ConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID sendBuffer,
                           DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped)
{
    if (!PrepareSocket(s, name, namelen, L"ConnectEx")) {
        return FALSE;
    }
    return Real_ConnectEx(s, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

int WSAAPI Hook_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (to && !PrepareSocket(s, to, tolen, L"sendto")) {
        return SOCKET_ERROR;
    }
    return Real_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags,
                          const sockaddr* to, int tolen, LPWSAOVERLAPPED overlapped,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (to && !PrepareSocket(s, to, tolen, L"WSASendTo")) {
        return SOCKET_ERROR;
    }
    return Real_WSASendTo(s, buffers, bufferCount, bytesSent, flags, to, tolen, overlapped, completion);
}

int WSAAPI Hook_WSASendMsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD bytesSent,
                           LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (msg && msg->name && !PrepareSocket(s, msg->name, msg->namelen, L"WSASendMsg")) {
        return SOCKET_ERROR;
    }
    return Real_WSASendMsg(s, msg, flags, bytesSent, overlapped, completion);
}

// bind() на "любой адрес" (0.0.0.0 / ::) подменяется адресом интерфейса — так, например,
// работает ConnectEx (.NET и др.) и UDP-сокеты, которые сначала привязываются, а потом шлют.
int WSAAPI Hook_bind(SOCKET s, const sockaddr* name, int namelen)
{
    SOCKADDR_INET a{};
    if (!ToInet(name, namelen, a) || !IsZeroAddress(a)) {
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
        Log(L"getsockname до соединения на двухстековом сокете: привязка к :: (возможна утечка)");
        BindDeferredAsRequested(s, *port);
    }
    return Real_getsockname(s, name, namelen);
}

int WSAAPI Hook_closesocket(SOCKET s)
{
    TakeDeferred(s);
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
bool HookApi(const char* name, T* detour, T** original)
{
    const MH_STATUS st = MH_CreateHookApi(L"ws2_32", name, reinterpret_cast<LPVOID>(detour),
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
    if (GetEnvironmentVariableW(kEnvAdapter, guid, static_cast<DWORD>(std::size(guid))) == 0) {
        return;   // правило не задано — DLL ничего не делает
    }
    if (!g_resolver.Init(guid)) {
        Log(L"неверный GUID интерфейса в %ls: %ls", kEnvAdapter, guid);
        return;
    }

    RuleConfig config;
    config.adapterGuid = guid;
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
    CreateDnsHooks(g_resolver);
    CreateProcessHooks(config);

    const MH_STATUS st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK) {
        Log(L"MH_EnableHook: %hs", MH_StatusToString(st));
        return;
    }
    g_installed = true;
    Log(L"активен в %ls, интерфейс %ls", exe, guid);
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
