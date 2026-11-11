#include "core/Socks5.h"

#include "core/Util.h"

#include <ws2tcpip.h>

#include <algorithm>
#include <cstring>
#include <format>

namespace approute {

namespace {

constexpr uint32_t kFakeBase = 0xC6120000u;   // 198.18.0.0
constexpr uint32_t kFakeSize = 0x20000u;      // /15
constexpr uint32_t kFakeUsable = kFakeSize - 2;   // без .0.0 и последнего адреса

std::optional<USHORT> ParsePort(std::wstring_view s)
{
    if (s.empty() || s.size() > 5) {
        return std::nullopt;
    }
    unsigned long v = 0;
    for (const wchar_t c : s) {
        if (c < L'0' || c > L'9') {
            return std::nullopt;
        }
        v = v * 10 + static_cast<unsigned long>(c - L'0');
    }
    if (v == 0 || v > 65535) {
        return std::nullopt;
    }
    return htons(static_cast<USHORT>(v));
}

std::string Lower(std::string_view s)
{
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; });
    return out;
}

void AppendPort(std::string& out, USHORT port)
{
    out.append(reinterpret_cast<const char*>(&port), 2);   // уже сетевой порядок
}

} // namespace

std::optional<SOCKADDR_INET> ParseProxyAddress(std::wstring_view text)
{
    SOCKADDR_INET out{};
    if (!text.empty() && text.front() == L'[') {
        const auto close = text.find(L']');
        if (close == std::wstring_view::npos || close + 1 >= text.size() || text[close + 1] != L':') {
            return std::nullopt;
        }
        const std::wstring host(text.substr(1, close - 1));
        const auto port = ParsePort(text.substr(close + 2));
        if (!port || InetPtonW(AF_INET6, host.c_str(), &out.Ipv6.sin6_addr) != 1) {
            return std::nullopt;
        }
        out.Ipv6.sin6_family = AF_INET6;
        out.Ipv6.sin6_port = *port;
        return out;
    }
    const auto colon = text.rfind(L':');
    if (colon == std::wstring_view::npos || text.find(L':') != colon) {
        return std::nullopt;   // IPv6 — только в квадратных скобках
    }
    const std::wstring host(text.substr(0, colon));
    const auto port = ParsePort(text.substr(colon + 1));
    if (!port || InetPtonW(AF_INET, host.c_str(), &out.Ipv4.sin_addr) != 1) {
        return std::nullopt;
    }
    out.Ipv4.sin_family = AF_INET;
    out.Ipv4.sin_port = *port;
    return out;
}

std::wstring FormatProxyAddress(const SOCKADDR_INET& address)
{
    if (address.si_family == AF_INET6) {
        return std::format(L"[{}]:{}", FormatAddress(address), ntohs(address.Ipv6.sin6_port));
    }
    return std::format(L"{}:{}", FormatAddress(address), ntohs(address.Ipv4.sin_port));
}

bool ProxyResponds(const SOCKADDR_INET& address, DWORD timeoutMs)
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return false;
    }
    bool ok = false;
    const SOCKET s = socket(address.si_family, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        u_long nonBlocking = 1;
        ioctlsocket(s, FIONBIO, &nonBlocking);
        const int len = address.si_family == AF_INET6 ? static_cast<int>(sizeof(sockaddr_in6))
                                                      : static_cast<int>(sizeof(sockaddr_in));
        if (connect(s, reinterpret_cast<const sockaddr*>(&address), len) == 0) {
            ok = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(s, &writable);
            fd_set failed;
            FD_ZERO(&failed);
            FD_SET(s, &failed);
            timeval tv{static_cast<long>(timeoutMs / 1000), static_cast<long>((timeoutMs % 1000) * 1000)};
            ok = select(0, nullptr, &writable, &failed, &tv) > 0 && FD_ISSET(s, &writable);
        }
        closesocket(s);
    }
    WSACleanup();
    return ok;
}

std::string Socks5Greeting()
{
    return std::string("\x05\x01\x00", 3);
}

bool Socks5NoAuthAccepted(std::string_view reply)
{
    return reply.size() == 2 && reply[0] == 0x05 && reply[1] == 0x00;
}

std::string Socks5ConnectRequest(const SOCKADDR_INET& target)
{
    std::string out("\x05\x01\x00", 3);
    if (target.si_family == AF_INET6) {
        out.push_back(0x04);
        out.append(reinterpret_cast<const char*>(&target.Ipv6.sin6_addr), 16);
        AppendPort(out, target.Ipv6.sin6_port);
    } else {
        out.push_back(0x01);
        out.append(reinterpret_cast<const char*>(&target.Ipv4.sin_addr), 4);
        AppendPort(out, target.Ipv4.sin_port);
    }
    return out;
}

std::optional<std::string> Socks5ConnectRequest(std::string_view host, USHORT port)
{
    if (host.empty() || host.size() > 255) {
        return std::nullopt;
    }
    std::string out("\x05\x01\x00\x03", 4);
    out.push_back(static_cast<char>(host.size()));
    out.append(host);
    AppendPort(out, port);
    return out;
}

std::optional<size_t> Socks5ReplyLength(std::string_view head)
{
    if (head.size() < 5 || head[0] != 0x05) {
        return std::nullopt;
    }
    switch (static_cast<uint8_t>(head[3])) {
    case 0x01: return 4 + 4 + 2;
    case 0x04: return 4 + 16 + 2;
    case 0x03: return 4 + 1 + static_cast<uint8_t>(head[4]) + 2;
    default: return std::nullopt;
    }
}

std::string Socks5UdpAssociateRequest()
{
    return std::string("\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10);
}

std::optional<SOCKADDR_INET> Socks5ReplyAddress(std::string_view reply)
{
    const auto total = Socks5ReplyLength(reply);
    if (!total || reply.size() < *total) {
        return std::nullopt;
    }
    SOCKADDR_INET a{};
    const auto* p = reinterpret_cast<const unsigned char*>(reply.data());
    switch (p[3]) {
    case 0x01:
        a.Ipv4.sin_family = AF_INET;
        std::memcpy(&a.Ipv4.sin_addr, p + 4, 4);
        std::memcpy(&a.Ipv4.sin_port, p + 8, 2);
        return a;
    case 0x04:
        a.Ipv6.sin6_family = AF_INET6;
        std::memcpy(&a.Ipv6.sin6_addr, p + 4, 16);
        std::memcpy(&a.Ipv6.sin6_port, p + 20, 2);
        return a;
    default:
        return std::nullopt;
    }
}

std::string Socks5UdpHeader(const SOCKADDR_INET& target)
{
    std::string out = Socks5ConnectRequest(target);
    out[1] = 0x00;   // RSV RSV FRAG вместо VER CMD RSV
    out[0] = 0x00;
    return out;
}

std::optional<std::string> Socks5UdpHeader(std::string_view host, USHORT port)
{
    auto out = Socks5ConnectRequest(host, port);
    if (out) {
        (*out)[0] = 0x00;
        (*out)[1] = 0x00;
    }
    return out;
}

std::optional<size_t> Socks5UdpHeaderLength(std::string_view datagram)
{
    if (datagram.size() < 5 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0) {
        return std::nullopt;
    }
    size_t length = 0;
    switch (static_cast<uint8_t>(datagram[3])) {
    case 0x01: length = 4 + 4 + 2; break;
    case 0x04: length = 4 + 16 + 2; break;
    case 0x03: length = 4 + 1 + static_cast<uint8_t>(datagram[4]) + 2; break;
    default: return std::nullopt;
    }
    if (datagram.size() < length) {
        return std::nullopt;
    }
    return length;
}

const wchar_t* Socks5ReplyText(uint8_t code)
{
    switch (code) {
    case 0x00: return L"успешно";
    case 0x01: return L"общий сбой прокси";
    case 0x02: return L"соединение запрещено правилами прокси";
    case 0x03: return L"сеть недоступна";
    case 0x04: return L"узел недоступен";
    case 0x05: return L"в соединении отказано";
    case 0x06: return L"истёк TTL";
    case 0x07: return L"команда не поддерживается";
    case 0x08: return L"тип адреса не поддерживается";
    default: return L"неизвестный ответ прокси";
    }
}

int Socks5ReplyToWsaError(uint8_t code)
{
    switch (code) {
    case 0x03: return WSAENETUNREACH;
    case 0x04: return WSAEHOSTUNREACH;
    case 0x05: return WSAECONNREFUSED;
    case 0x06: return WSAETIMEDOUT;
    default: return WSAECONNREFUSED;
    }
}

SOCKADDR_INET FakeIpPool::Allocate(std::string_view name)
{
    const std::string key = Lower(name);
    AcquireSRWLockExclusive(&lock_);
    uint32_t index = 0;
    if (const auto it = byName_.find(key); it != byName_.end()) {
        index = it->second;
    } else {
        index = next_;
        next_ = (next_ + 1) % kFakeUsable;
        if (index < byIndex_.size()) {
            byName_.erase(byIndex_[index]);   // пул исчерпан — переиспользуем старейший
            byIndex_[index] = key;
        } else {
            byIndex_.push_back(key);
        }
        byName_[key] = index;
    }
    ReleaseSRWLockExclusive(&lock_);

    SOCKADDR_INET out{};
    out.Ipv4.sin_family = AF_INET;
    out.Ipv4.sin_addr.s_addr = htonl(kFakeBase + 1 + index);
    return out;
}

bool FakeIpPool::InRange(const SOCKADDR_INET& address)
{
    uint32_t v4 = 0;
    if (address.si_family == AF_INET) {
        v4 = ntohl(address.Ipv4.sin_addr.s_addr);
    } else if (address.si_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&address.Ipv6.sin6_addr)) {
        std::memcpy(&v4, &address.Ipv6.sin6_addr.u.Byte[12], 4);
        v4 = ntohl(v4);
    } else {
        return false;
    }
    return (v4 & ~(kFakeSize - 1)) == kFakeBase;
}

std::optional<std::string> FakeIpPool::Lookup(const SOCKADDR_INET& address) const
{
    if (!InRange(address)) {
        return std::nullopt;
    }
    uint32_t v4 = 0;
    if (address.si_family == AF_INET) {
        v4 = ntohl(address.Ipv4.sin_addr.s_addr);
    } else {
        std::memcpy(&v4, &address.Ipv6.sin6_addr.u.Byte[12], 4);
        v4 = ntohl(v4);
    }
    const uint32_t offset = v4 - kFakeBase;
    if (offset == 0) {
        return std::nullopt;
    }
    std::optional<std::string> out;
    AcquireSRWLockShared(&lock_);
    if (offset - 1 < byIndex_.size()) {
        out = byIndex_[offset - 1];
    }
    ReleaseSRWLockShared(&lock_);
    return out;
}

std::optional<std::string> ProxyHostName(std::wstring_view name)
{
    while (!name.empty() && name.back() == L'.') {
        name.remove_suffix(1);
    }
    if (name.empty() || name.size() > 253) {
        return std::nullopt;
    }
    wchar_t ascii[256] = {};
    const int n = IdnToAscii(IDN_ALLOW_UNASSIGNED, name.data(), static_cast<int>(name.size()), ascii,
                             static_cast<int>(std::size(ascii)));
    if (n <= 0) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        if (ascii[i] == 0 || ascii[i] > 0x7F) {
            return std::nullopt;
        }
        out.push_back(static_cast<char>(ascii[i]));
    }
    return out;
}

} // namespace approute
